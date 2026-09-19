# ADR 0038: Rotatable JWT trust sets

## Status

Accepted

## Context

MON previously accepted a single configured RSA public key for control-plane JWT validation.
That creates an avoidable rotation outage: replacing one key immediately invalidates tokens signed
by the prior key, while keeping the old key configured prevents a clean cutover.

The control plane needs overlapping public-key trust during issuer rotation without making
authentication depend on a live identity-provider network request.

## Decision

MON supports a local JWKS trust set in addition to the legacy single-PEM compatibility mode.

The preferred production configuration is MON_AUTH_JWKS_FILE. The file contains public RSA
verification keys with unique kid values. RS256 is the only accepted JWKS algorithm in this
implementation. Symmetric keys, private RSA parameters, duplicate key IDs, unsupported key uses,
and unsupported algorithms fail configuration.

The cached authenticator checks the JWKS file identity, size, and nanosecond modification time
for every verification request. When the file changes it parses and validates the complete new
trust set before replacing the active in-memory set. Operations should rotate the file with an
atomic filesystem replace.

A malformed or unreadable changed JWKS file makes authentication unavailable. MON does not keep
accepting a stale key set after a failed reload because doing so could continue trusting a key
that an operator intended to revoke.

Each JWKS-authenticated token must carry a kid header that selects one trusted key. Unknown or
missing key IDs fail authentication. Issuer, audience, signature, exp, iat, subject, role and
site-scope validation remain mandatory.

MON does not fetch a remote JWKS URL in the request path. Identity-provider synchronization is an
operations concern and should materialize a validated local file through the deployment secret or
configuration mechanism. This keeps SaaS identity-provider network loss from silently changing
MON's authentication behavior.

Legacy MON_AUTH_PUBLIC_KEY_PEM and MON_AUTH_PUBLIC_KEY_FILE remain supported for small deployments,
but they cannot be configured at the same time as a JWKS source.

## Consequences

- Signing-key rotations can overlap old and new public keys without a control-plane restart.
- Removal of a key becomes effective when the local JWKS file is atomically replaced.
- Authentication fails closed on corrupt rotation material.
- MON still has no dependency on a live remote JWKS endpoint in the request path.
- Deployments are responsible for protecting and atomically updating the public JWKS file.
