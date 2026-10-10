#!/usr/bin/env python3
"""Bounded, VM-only local resource pressure with observed JSON evidence.

This does not generate network attack traffic or inject simulated MON telemetry.
No bare-metal runs, unbounded allocations, full-disk writes or elevated execution.
"""
# ruff: noqa: E501  # audit/report strings are more readable unwrapped.
from __future__ import annotations

import argparse
import datetime as dt
import getpass
import hashlib
import json
import multiprocessing as mp
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

MiB = 1024 * 1024
MAX_DURATION = 60
MAX_MEMORY_MIB = 512
MAX_DISK_MIB = 512
MAX_CPU_WORKERS = 2
SAMPLE_INTERVAL = 0.5
RECOVERY_SECONDS = 3


class PressureSafetyError(ValueError):
    """Refusal to run an unsafe or unqualified workload."""


def iso_timestamp() -> str:
    return dt.datetime.now(dt.UTC).isoformat()


def read_meminfo(path: Path = Path("/proc/meminfo")) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        label, _, remainder = line.partition(":")
        if remainder:
            parts = remainder.split()
            if parts and parts[0].isdigit():
                values[label] = int(parts[0]) * 1024
    return values


def read_cpu(path: Path = Path("/proc/stat")) -> tuple[int, int]:
    first = path.read_text(encoding="utf-8").splitlines()[0].split()
    if first[0] != "cpu" or len(first) < 5:
        raise PressureSafetyError("invalid /proc/stat CPU counters")
    ticks = list(map(int, first[1:]))
    idle = ticks[3] + (ticks[4] if len(ticks) > 4 else 0)
    return sum(ticks), idle


def cpu_percent(before: tuple[int, int], after: tuple[int, int]) -> float | None:
    total = after[0] - before[0]
    idle = after[1] - before[1]
    if total <= 0 or idle < 0:
        return None
    return round(100 * max(0, min(1, 1 - idle / total)), 2)


def take_sample(scratch: Path, previous: tuple[int, int] | None) -> tuple[dict, tuple[int, int]]:
    ticks = read_cpu()
    mem = read_meminfo()
    disk = shutil.disk_usage(scratch)
    sample = {
        "timestamp": iso_timestamp(),
        "cpu_system_percent": cpu_percent(previous, ticks) if previous else None,
        "mem_available_bytes": mem.get("MemAvailable"),
        "mem_total_bytes": mem.get("MemTotal"),
        "filesystem_available_bytes": disk.free,
        "filesystem_total_bytes": disk.total,
    }
    if sample["mem_available_bytes"] is None or sample["mem_total_bytes"] is None:
        raise PressureSafetyError("unavailable Linux memory counters")
    return sample, ticks


def vm_gate(*, approved: bool) -> str:
    if not approved:
        raise PressureSafetyError("--ack-disposable-vm is mandatory")
    if os.geteuid() == 0:
        raise PressureSafetyError("run unprivileged inside a disposable VM; do not use sudo/root")
    if shutil.which("systemd-detect-virt") is None:
        raise PressureSafetyError("systemd-detect-virt is required for positive VM verification")
    result = subprocess.run(
        ["systemd-detect-virt", "--vm"], capture_output=True, text=True, check=False
    )
    if result.returncode != 0 or not result.stdout.strip():
        raise PressureSafetyError(
            "not a verified virtual machine: refusing resource pressure on a physical host/container"
        )
    return result.stdout.strip()


def workload_budget(
    *, mode: str, duration: int, workers: int, memory_mib: int, disk_mib: int,
    mem_available: int, mem_total: int, fs_available: int,
) -> dict[str, int]:
    if mode not in ("cpu", "memory", "disk"):
        raise PressureSafetyError("unknown workload mode")
    if not 5 <= duration <= MAX_DURATION:
        raise PressureSafetyError("duration must be between 5 and 60 seconds")
    if not 1 <= workers <= MAX_CPU_WORKERS:
        raise PressureSafetyError("CPU workers must be between 1 and 2")
    if mode == "memory":
        # Cap below half of currently available VM memory, and 25% of total.
        max_bytes = min(MAX_MEMORY_MIB * MiB, mem_available // 2, mem_total // 4)
        if memory_mib < 1 or memory_mib * MiB > max_bytes:
            raise PressureSafetyError(
                f"memory request exceeds bounded VM budget ({max_bytes // MiB} MiB)"
            )
    if mode == "disk":
        # Never fill a volume; leave at least 80% of observed free space intact.
        max_bytes = min(MAX_DISK_MIB * MiB, fs_available // 5)
        if disk_mib < 1 or disk_mib * MiB > max_bytes:
            raise PressureSafetyError(
                f"disk request exceeds bounded VM budget ({max_bytes // MiB} MiB)"
            )
    return {
        "duration_seconds": duration,
        "cpu_workers": workers if mode == "cpu" else 0,
        "memory_bytes_limit": memory_mib * MiB if mode == "memory" else 0,
        "disk_bytes_limit": disk_mib * MiB if mode == "disk" else 0,
    }


def cpu_worker(stop: mp.Event, duration: int) -> None:
    # Independent TTL: survives parent SSH loss/abnormal controller termination.
    deadline = time.monotonic() + min(duration + 2, MAX_DURATION + 2)
    payload = bytearray(b"MON-disposable-vm-local-pressure")
    while not stop.is_set() and time.monotonic() < deadline:
        hashlib.sha256(payload).digest()
        payload[0] = (payload[0] + 1) % 256


def memory_worker(stop: mp.Event, byte_limit: int, duration: int) -> None:
    deadline = time.monotonic() + min(duration + 2, MAX_DURATION + 2)
    chunks = []
    allocated = 0
    while allocated < byte_limit and not stop.is_set() and time.monotonic() < deadline:
        chunk_size = min(4 * MiB, byte_limit - allocated)
        chunk = bytearray(chunk_size)
        for index in range(0, chunk_size, 4096):
            chunk[index] = 1
        chunks.append(chunk)
        allocated += chunk_size
    while time.monotonic() < deadline and not stop.wait(0.1):
        # Keep memory resident only within its own independent TTL.
        if chunks:
            chunks[0][0] ^= 1


def disk_worker(stop: mp.Event, byte_limit: int, output: str, duration: int) -> None:
    # Only a new file under the operator-designated disposable VM scratch directory.
    deadline = time.monotonic() + min(duration + 2, MAX_DURATION + 2)
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    written = 0
    block = b"x" * MiB
    try:
        while written < byte_limit and not stop.is_set() and time.monotonic() < deadline:
            n = os.write(fd, block[: min(MiB, byte_limit - written)])
            if n <= 0:
                raise OSError("disk write returned no progress")
            written += n
        os.fsync(fd)
        while time.monotonic() < deadline and not stop.wait(0.1):
            pass
    finally:
        os.close(fd)


def worker_function(mode: str):
    return {"cpu": cpu_worker, "memory": memory_worker, "disk": disk_worker}[mode]


def atomic_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def run_experiment(args: argparse.Namespace) -> dict:
    # Explicitly qualify the VM BEFORE any test files or workers are created.
    hypervisor = vm_gate(approved=args.ack_disposable_vm)
    scratch = args.scratch_dir.expanduser().resolve(strict=True)
    if not scratch.is_dir() or scratch == Path("/"):
        raise PressureSafetyError("scratch must be an existing directory inside the disposable VM")
    report = args.report.expanduser().resolve()
    if report.exists():
        raise PressureSafetyError(f"report file already exists: {report}")
    if report == scratch or report == Path("/"):
        raise PressureSafetyError("invalid report destination")

    baseline, ticks = take_sample(scratch, None)
    budget = workload_budget(
        mode=args.mode, duration=args.duration_seconds, workers=args.workers,
        memory_mib=args.memory_mib, disk_mib=args.disk_mib,
        mem_available=baseline["mem_available_bytes"],
        mem_total=baseline["mem_total_bytes"],
        fs_available=baseline["filesystem_available_bytes"],
    )

    started = iso_timestamp()
    token = f"mon-pressure-{os.getpid()}-{time.monotonic_ns()}"
    scratch_file = scratch / f"{token}.bin"
    audit: dict = {
        "schema_version": "mon.lab.pressure.v1",
        "observed": True,
        "source": "linux-procfs-and-statvfs",
        "operator": getpass.getuser(),
        "host": socket.gethostname(),
        "hypervisor": hypervisor,
        "safety_scope": "local-disposable-vm-only",
        "policy_decision": "local-operator-approved-bounded-pressure",
        "actor": getpass.getuser(),
        "confidence": "measured-host-counters-not-security-detection-confidence",
        "reason": "measure resource usage under controlled local load",
        "ttl_seconds": budget["duration_seconds"],
        "blast_radius_estimate": "single disposable VM; no network traffic generated",
        "action": args.mode,
        "rollback": "terminate workers and remove only the uniquely created scratch file",
        "started_at": started,
        "limits": budget,
        "baseline": baseline,
        "samples": [],
        "result": "IN_PROGRESS",
    }

    stop = mp.Event()
    processes: list[mp.Process] = []
    error: BaseException | None = None
    interrupted = False
    original_handlers = {}

    def request_stop(signum, _frame):
        nonlocal interrupted
        interrupted = True
        stop.set()

    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            original_handlers[sig] = signal.getsignal(sig)
            signal.signal(sig, request_stop)
        count = budget["cpu_workers"] if args.mode == "cpu" else 1
        for _ in range(count):
            if args.mode == "cpu":
                parameters = (stop, budget["duration_seconds"])
            elif args.mode == "memory":
                parameters = (stop, budget["memory_bytes_limit"], budget["duration_seconds"])
            else:
                parameters = (
                    stop,
                    budget["disk_bytes_limit"],
                    str(scratch_file),
                    budget["duration_seconds"],
                )
            process = mp.Process(
                target=worker_function(args.mode),
                args=parameters,
                daemon=True,
            )
            process.start()
            processes.append(process)
        deadline = time.monotonic() + budget["duration_seconds"]
        while time.monotonic() < deadline and not stop.is_set():
            sample, ticks = take_sample(scratch, ticks)
            audit["samples"].append(sample)
            if any(p.exitcode is not None and p.exitcode != 0 for p in processes):
                raise RuntimeError("one or more pressure workers exited with an error")
            time.sleep(min(SAMPLE_INTERVAL, max(0.0, deadline - time.monotonic())))
    except BaseException as exc:
        error = exc
    finally:
        stop.set()
        for process in processes:
            process.join(timeout=1)
            if process.is_alive():
                process.terminate()
                process.join(timeout=2)
            if process.is_alive():
                process.kill()
                process.join(timeout=2)
        file_bytes = scratch_file.stat().st_size if scratch_file.exists() else 0
        scratch_file.unlink(missing_ok=True)
        for sig, old in original_handlers.items():
            signal.signal(sig, old)
        # Recovery is observed, not inferred from workload process completion.
        time.sleep(RECOVERY_SECONDS)
        after, _ = take_sample(scratch, None)
        audit["ended_at"] = iso_timestamp()
        audit["recovery_observation"] = after
        audit["scratch_file_bytes_written"] = file_bytes
        audit["scratch_file_removed"] = not scratch_file.exists()
        audit["worker_exitcodes"] = [p.exitcode for p in processes]
        audit["peak_cpu_system_percent"] = max(
            (s["cpu_system_percent"] for s in audit["samples"]
             if s["cpu_system_percent"] is not None),
            default=None,
        )
        audit["lowest_mem_available_bytes"] = min(
            (s["mem_available_bytes"] for s in audit["samples"]),
            default=None,
        )
        audit["result"] = (
            "INTERRUPTED" if interrupted else "FAILED" if error else
            "COMPLETED_WITH_OBSERVED_RECOVERY_SAMPLE"
        )
        if error:
            audit["error"] = str(error)
        audit["audit_record"] = {
            "actor": audit["actor"],
            "action": audit["action"],
            "target": audit["host"],
            "occurred_at": audit["started_at"],
            "completed_at": audit["ended_at"],
            "result": audit["result"],
        }
        atomic_json(report, audit)
    if error:
        raise RuntimeError(f"pressure experiment failed; evidence saved to {report}: {error}")
    if interrupted:
        raise RuntimeError(f"pressure experiment interrupted; evidence saved to {report}")
    return audit


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("cpu", "memory", "disk"), required=True)
    parser.add_argument("--duration-seconds", type=int, default=15)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--memory-mib", type=int, default=128)
    parser.add_argument("--disk-mib", type=int, default=128)
    parser.add_argument("--scratch-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--ack-disposable-vm", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        audit = run_experiment(args)
    except (PressureSafetyError, ValueError, OSError, RuntimeError) as exc:
        print(f"MON bounded pressure: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({
        "report": str(args.report),
        "result": audit["result"],
        "peak_cpu_system_percent": audit["peak_cpu_system_percent"],
        "scratch_file_bytes_written": audit["scratch_file_bytes_written"],
        "scratch_file_removed": audit["scratch_file_removed"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
