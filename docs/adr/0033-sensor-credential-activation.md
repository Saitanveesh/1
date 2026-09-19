# ADR 0033: Crash-safe sensor credential activation and proactive renewal

## Status

Accepted

## Context

ADR 0032 added control-plane sensor enrollment, renewal, revocation, durable site trust,
and fleet heartbeats. The remaining credential boundary was local activation: collectors
still depended on a fixed certificate/key pair provisioned outside MON.

Replacing two live PEM files in place is unsafe. A crash between key replacement and
certificate replacement can leave a mismatched pair. A crash after the control plane rotates
the sensor identity but before the new certificate is durably stored can also strand the
collector once the old certificate overlap expires.

MON therefore needs a local credential protocol that treats rotation as a durable state
transition, not as two unrelated file writes.

## Decision

Zeek and Suricata collectors now use a managed credential-generation store under the sensor
state directory.

### Directory model

Each tenant/site/sensor identity receives a deterministic hashed directory under
MON_SENSOR_STATE_DIR/credentials/<scope-digest>/.

The store contains scope-bound metadata, immutable credential generation directories, one
atomic active.json pointer, one durable pending.json renewal record while rotation is
incomplete, and a process-shared non-blocking rotation lock.

Generation directories contain the private key, certificate when available, CSR for pending
renewals, and generation metadata. Private keys and sensitive JSON state are written with
mode 0600; credential directories are mode 0700 on POSIX systems.

The original MON_SENSOR_CLIENT_CERT_FILE and MON_SENSOR_CLIENT_KEY_FILE are bootstrap inputs
only. Once the managed store has an active generation, later collector starts use that
durable generation and do not require the bootstrap files to still exist.

MON_SENSOR_SERVER_CA_CERT_FILE remains an external configuration dependency because it
authenticates the local sensor-ingress server rather than the sensor client identity.

### Atomic activation protocol

The active credential is never defined by overwriting the live certificate/key pair.

A new rotation proceeds as follows:

1. generate a new private key and CSR;
2. durably create a new generation directory;
3. durably write pending.json containing the generation id, original certificate
   fingerprint, CSR, and creation time;
4. submit the exact persisted CSR through the currently authenticated sensor connection;
5. validate the returned certificate against the pending private key, expected
   tenant/site/sensor SPIFFE URI, fingerprint, expiry, client-auth EKU, issuing CA, and CA
   signature;
6. durably write the returned certificate and issuing CA into the pending generation;
7. build a candidate mTLS context and prove that the sensor ingress accepts the new
   certificate;
8. atomically replace active.json so it points at the complete generation;
9. switch the running HTTP client to the already-proven new SSL context;
10. remove the pending marker and retain at most the current plus one previous generation.

The active pointer is therefore the commit record. A partially written generation is never
active.

On POSIX/Linux the implementation fsyncs credential files, generation directories, and the
containing directory around rename/replace operations. That is the production durability
claim for this tranche.

Windows directory fsync is not provided by this implementation. Windows-native credential
activation therefore remains outside the production release claim until it has a separate
native crash/power-loss validation gate.

### Lost-response and restart recovery

The CSR and private key are persisted before the renewal request leaves the process.

This matters because ADR 0032 makes same-CSR renewal replay idempotent. If the HTTP response
is lost or the collector restarts, MON resends the same CSR rather than generating another
key.

If the renewed certificate was already persisted but activation did not complete, restart
first probes that pending certificate. If the ingress accepts it, MON can activate it without
needing the old certificate to authenticate again.

This specifically covers the case where the old overlap window has already expired but the
new certificate reached durable local storage before the crash.

There remains one bounded protocol gap: if the control plane successfully rotates the
identity, the collector crashes before the returned certificate reaches durable storage, and
the collector remains down beyond the old-certificate overlap window, automatic recovery
cannot reconstruct the new private credential from the control plane. MON reports this
boundary explicitly rather than pretending it is solved. The operator must recover or
reenroll that sensor identity.

### Probe before commit

Receiving a syntactically valid certificate is not enough to activate it.

Before switching active.json, the collector opens a candidate mTLS connection to the sensor
ingress health endpoint using the new certificate. The returned tenant, site, and sensor
identity must match the configured collector.

If the probe fails, the old generation remains active and the pending generation is preserved
for retry.

### Shared-process safety

Multiple collector processes can observe the same managed sensor credential store.

Only one process may perform a rotation transition at a time. The store uses a non-blocking
OS file lock. A competing process receives a BUSY result and retries soon rather than
starting a second CSR transition.

Each collector client tracks the fingerprint it is currently using. During periodic
credential checks, if another process has already advanced the durable active pointer, the
collector probes and loads that active generation before continuing. This keeps collectors
sharing one sensor identity from remaining on the retiring certificate until overlap expiry.

The recommended deployment remains one logical sensor identity per collector instance when
operationally practical, because it improves attribution and limits shared-credential blast
radius.

### Proactive renewal schedule

Collectors check managed credential state independently of telemetry health.

Defaults are MON_SENSOR_RENEW_BEFORE_SECONDS=604800 and
MON_SENSOR_RENEW_CHECK_INTERVAL_SECONDS=300. Renewal therefore begins seven days before
certificate expiry and credential state is checked every five minutes.

The renewal-check interval is capped at 15 minutes so a process sharing an identity can
converge on a peer-rotated credential well inside the default one-hour overlap from ADR 0032.

A configured renewal lead time must be shorter than the active certificate's actual lifetime.
MON fails the renewal check instead of entering a tight endless rotation loop if this
invariant is violated.

Credential rotation is attempted before the next telemetry batch is sent. A rotation failure
does not discard telemetry; collection continues with the current credential while it remains
usable, and the collector heartbeat becomes DEGRADED with the credential error.

### Key encryption

If MON_SENSOR_CLIENT_KEY_PASSWORD is configured, newly generated managed private keys use
the same password and PKCS#8 encryption. The password is not persisted in the credential
store.

Changing or removing that password without rewrapping the managed key material causes startup
to fail closed rather than silently generating a new identity.

## Crash matrix

- crash before pending generation creation: old active generation remains authoritative;
- crash after generation creation but before pending.json: incomplete unreferenced generation
  is never active and can be discarded;
- crash after pending.json but before renewal request: same persisted CSR is sent later;
- renewal request succeeds but response is lost: same CSR is replayed through ADR 0032;
- certificate is persisted but probe fails or a crash occurs: pending certificate remains and
  is probed again after restart;
- probe succeeds but crash occurs before active-pointer replace: old active pointer remains and
  the pending new certificate is retried;
- active pointer is replaced but crash occurs before pending-marker cleanup: startup observes
  that active and pending generation ids match and removes the stale marker;
- active pointer is replaced but the running client has not switched yet: restart uses the new
  active generation, and a still-running peer detects fingerprint drift on its next check;
- another process is already rotating the same identity: the second process does not issue a
  CSR and retries later.

## Consequences

Collector credential rotation no longer depends on unsafe in-place certificate/key
replacement.

The sensor private key remains local and is never returned to the control plane.

The local state directory now contains long-lived sensitive key material and must be protected
as a secret-bearing directory. Backups, support bundles, and diagnostics must not copy private
keys by default.

A future hardening tranche should add platform-specific filesystem durability tests,
secret-at-rest integration where available, and operator-visible credential-rotation status
without exposing key material.
