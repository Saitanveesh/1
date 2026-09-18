# ADR 0011: Evidence-backed asset discovery and short-window telemetry

Status: Accepted

## Decision

The shared security pipeline now updates an Asset Engine and a 60-second operational
Telemetry Engine for every accepted event.

Asset identity preference is:

1. sensor-asserted asset ID;
2. valid unicast source MAC;
3. source IP observation.

IP-only identity is explicitly labelled `SOURCE_IP_OBSERVATION_ONLY` because address
ownership can change. MON does not promote an observed name to a canonical hostname
unless it arrived from an explicit passive/endpoint source such as DHCP, mDNS, LLMNR,
NBNS or endpoint telemetry.

A TCP service is recorded only when the event indicates a source-side SYN+ACK and
provides the source port.

## Measurement semantics

Telemetry `observation_count` is a security-event count, not a packet count.

Packet and byte values are nullable. They remain null unless sensors actually supply
those measurements. Rates are not emitted until the observation window spans at least
one second.

Measured packet/byte totals sum only values supplied by sensors. Their names deliberately
avoid implying complete link counters when some events have no measurement.

## UI

The operator console now exposes real Assets and Telemetry views. Missing values render
as an em dash rather than zero. The former Overview "Network Health" label was corrected
to "Control Plane Link" because WebSocket connectivity alone is not network health.
