from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "lab_three_pressure.py"
MiB = 1024 * 1024


def module():
    spec = importlib.util.spec_from_file_location("mon_lab_three_pressure", SCRIPT)
    assert spec is not None and spec.loader is not None
    result = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = result
    spec.loader.exec_module(result)
    return result


def budget(**kwargs):
    arguments = dict(
        mode="memory",
        duration=15,
        workers=1,
        memory_mib=128,
        disk_mib=128,
        mem_available=2 * 1024 * MiB,
        mem_total=4 * 1024 * MiB,
        fs_available=10 * 1024 * MiB,
    )
    arguments.update(kwargs)
    return module().workload_budget(**arguments)


def test_bounds_memory_never_exceed_half_available_or_quarter_total():
    assert budget()["memory_bytes_limit"] == 128 * MiB
    with pytest.raises(ValueError, match="VM budget"):
        budget(memory_mib=513)
    with pytest.raises(ValueError, match="VM budget"):
        budget(memory_mib=128, mem_available=200 * MiB)
    with pytest.raises(ValueError, match="VM budget"):
        budget(memory_mib=128, mem_total=400 * MiB)


def test_bounds_disk_never_fill_volume():
    result = budget(mode="disk", disk_mib=128)
    assert result["disk_bytes_limit"] == 128 * MiB
    with pytest.raises(ValueError, match="VM budget"):
        budget(mode="disk", disk_mib=128, fs_available=400 * MiB)
    with pytest.raises(ValueError, match="VM budget"):
        budget(mode="disk", disk_mib=513)


@pytest.mark.parametrize("duration", [0, 4, 61, 1000])
def test_bounded_runtime(duration):
    with pytest.raises(ValueError, match="duration"):
        budget(duration=duration)


@pytest.mark.parametrize("workers", [0, 3, 100])
def test_workers_cannot_be_unbounded(workers):
    with pytest.raises(ValueError, match="workers"):
        budget(mode="cpu", workers=workers)


def test_vm_gate_denies_missing_operator_ack(monkeypatch):
    pressure = module()
    with pytest.raises(ValueError, match="ack-disposable-vm"):
        pressure.vm_gate(approved=False)


def test_vm_gate_denies_root(monkeypatch):
    pressure = module()
    monkeypatch.setattr(pressure.os, "geteuid", lambda: 0)
    with pytest.raises(ValueError, match="unprivileged"):
        pressure.vm_gate(approved=True)


def test_vm_gate_denies_non_vm_even_when_approved(monkeypatch):
    pressure = module()
    monkeypatch.setattr(pressure.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(pressure.shutil, "which", lambda tool: "/usr/bin/systemd-detect-virt")
    monkeypatch.setattr(
        pressure.subprocess, "run",
        lambda *a, **kw: SimpleNamespace(returncode=1, stdout="", stderr="none"),
    )
    with pytest.raises(ValueError, match="not a verified virtual machine"):
        pressure.vm_gate(approved=True)


def test_vm_gate_accepts_positive_vm_proof(monkeypatch):
    pressure = module()
    monkeypatch.setattr(pressure.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(pressure.shutil, "which", lambda tool: "/usr/bin/systemd-detect-virt")
    monkeypatch.setattr(
        pressure.subprocess, "run",
        lambda *a, **kw: SimpleNamespace(returncode=0, stdout="kvm\n", stderr=""),
    )
    assert pressure.vm_gate(approved=True) == "kvm"


def test_cpu_percent_is_derived_from_real_counter_deltas():
    pressure = module()
    assert pressure.cpu_percent((1000, 600), (1100, 650)) == 50.0
    assert pressure.cpu_percent((1000, 600), (1000, 600)) is None


def test_parse_real_proc_memory_and_cpu(tmp_path):
    pressure = module()
    mem = tmp_path / "meminfo"
    mem.write_text("MemTotal: 4000 kB\nMemAvailable: 2000 kB\n")
    assert pressure.read_meminfo(mem)["MemAvailable"] == 2000 * 1024
    cpu = tmp_path / "stat"
    cpu.write_text("cpu 10 0 2 30 8 1 1 0 0 0\n")
    assert pressure.read_cpu(cpu) == (52, 38)


def test_json_report_has_no_fabricated_values(tmp_path):
    pressure = module()
    report = tmp_path / "report.json"
    pressure.atomic_json(
        report,
        {"schema_version": "mon.lab.pressure.v1", "observed": True, "samples": []},
    )
    assert report.stat().st_mode & 0o077 == 0
    assert '"samples": []' in report.read_text()
    assert not list(tmp_path.glob("*.tmp"))


def test_no_network_or_host_unbounded_pressure_commands():
    source = SCRIPT.read_text()
    assert "nmap " not in source
    assert "sshpass" not in source
    assert "dd if=" not in source
    assert "mkfs" not in source
    assert "rm -rf" not in source
    assert "fallocate" not in source
