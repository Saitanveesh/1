# ADR 0037: Compact laboratory deployment

Status: Proposed

Context: Manual setup across seven hosts is operationally expensive.

Decision: Support a compact three-host laboratory. The first host runs the MON control plane, site runtime, database and network sensor. The second runs Linux endpoint telemetry. The third provides isolated lab traffic. Remote administration uses Tailscale, and a dedicated WireGuard overlay carries the observable lab flows.

Consequences: A single combined MON host is a failure domain. This is a development topology, not a production high-availability deployment. The full multi-tenant architecture remains separate in code.

Verification: Validate with CI and disposable Ubuntu VMs, followed by verified real sensor telemetry, operator approval, bounded response, recovery and audit.