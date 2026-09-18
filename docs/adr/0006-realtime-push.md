# ADR 0006: Push-based real-time operator updates

Status: Accepted

## Decision

MON operator clients receive tenant/site-scoped state changes through WebSocket push.
The operator UI must not use a fixed 2--3 second polling loop for normal live updates.

Event ingestion runs outside the asyncio event loop so database/detection work cannot
block WebSocket delivery. After an event is processed, MON immediately publishes an
`event.processed` envelope containing the event plus any findings and incidents.

Assets, manual incidents, enforcement configuration and response plans also publish
state-change messages.

## Delivery behavior

Each subscriber has a bounded queue. A slow browser is never allowed to backpressure
security-event ingestion. If the queue fills, the oldest queued update is dropped and
the drop count is reported in the next heartbeat.

Messages are scoped by tenant and site and have an increasing scope-local sequence
number.

A reconnecting client first opens the WebSocket, receives `stream.ready`, then requests
`/api/v1/live/snapshot`. The snapshot restores current findings/incidents/graph state,
while messages queued after connection cover concurrent changes. Object IDs make
re-applying an overlapping update safe at the UI state layer.

## Performance objective

There is no artificial refresh delay. Under nominal local/network conditions the design
target is sub-second operator visibility after backend processing, but network latency,
sensor delivery time and server load can increase end-to-end latency.

## Scale-out limitation

The first implementation uses in-process fan-out. Before running multiple control-plane
replicas, this interface must be backed by a shared broker such as NATS or Redis Streams
so a WebSocket attached to one replica receives updates produced by another replica.
