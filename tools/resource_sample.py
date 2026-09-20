"""One bounded resource sample of a process, for the fabric load probe's sampler hook.

usage: python tools/resource_sample.py <pid>
Prints one JSON object with measured values only (Linux /proc). No secrets.
"""

# ruff: noqa: E501
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path


def sample(pid: int) -> dict[str, object]:
    ticks = os.sysconf("SC_CLK_TCK")
    stat = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    status = dict(
        line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines() if ":" in line
    )
    meminfo = dict(
        line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines() if ":" in line
    )
    return {
        "pid": pid,
        "sampled_at": time.time(),
        "process_user_cpu_seconds": int(stat[11]) / ticks,
        "process_system_cpu_seconds": int(stat[12]) / ticks,
        "process_rss_kb": int(status["VmRSS"].split()[0]),
        "process_threads": int(status["Threads"].strip()),
        "host_cpu_count": os.cpu_count(),
        "host_load_1m": float(Path("/proc/loadavg").read_text().split()[0]),
        "host_mem_total_kb": int(meminfo["MemTotal"].split()[0]),
        "host_mem_available_kb": int(meminfo["MemAvailable"].split()[0]),
    }


if __name__ == "__main__":
    print(json.dumps(sample(int(sys.argv[1]))))
