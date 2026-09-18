# ADR 0012: Expanded evidence-bounded network detection

Status: Accepted

## Decision

MON separates observable network behaviors into distinct findings rather than using a
single generic "attack" detector.

The streaming engine now covers:

- TCP SYN reconnaissance shape;
- concentrated TCP SYN flood pressure;
- concentrated UDP flood pressure;
- concentrated ICMP flood pressure;
- high-rate administrative-service connection attempts;
- ICMP host discovery;
- DNS query-rate anomalies;
- long/high-diversity DNS tunneling-shaped queries;
- ARP discovery sweeps;
- east-west administrative-service sweeps;
- periodic endpoint communication shape; and
- network IDS signature events.

## Claim discipline

A pressure detector does not claim service outage. Administrative connection attempts do
not claim failed or successful authentication. DNS tunneling shape does not claim
exfiltration. Periodicity does not claim command-and-control. IDS alerts are retained as
signature matches rather than automatically promoted to confirmed compromise.

## State safety

Detection state is protected by a lock because API ingestion can execute concurrently in
worker threads. Sliding windows tolerate out-of-order observations and prune relative to
the newest observation in the window.

Thresholds are represented by a typed configuration object. They are defaults, not a
claim that one threshold is correct for every network. Site-specific baseline/policy
configuration will be added after durable policy management.
