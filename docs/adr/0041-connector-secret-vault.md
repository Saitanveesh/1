# ADR 0041: Encrypted connector-secret vault and reference-only credentials

## Status

Accepted

## Context

Infrastructure connectors will eventually hold credentials capable of changing firewalls,
routers, NAC, switches, cloud controls, WAFs, and upstream mitigations. Those credentials must
not be copied into enforcement-point JSON, telemetry, browser payloads, response/audit detail,
or command-line arguments.

ADR 0026 required connector credentials to be represented by secret identifiers rather than
embedded values. MON now needs the storage and key-management boundary behind those identifiers
before production connectors are added.

## Decision

MON stores connector credentials in a dedicated `connector_secrets` table. The table has no
general JSON payload. It contains tenant/site/secret identity, encryption-key identity, an
AEAD nonce, ciphertext, and timestamps.

Secret plaintext is encrypted with AES-256-GCM before it is written to the database.

Authenticated additional data binds the ciphertext to:

- the MON connector-secret format/version;
- `tenant_id`;
- `site_id`;
- `secret_id`.

Moving ciphertext to a different tenant, site, or secret identifier therefore causes
authentication failure rather than returning plaintext.

### Keyring boundary

Encryption keys are not stored in PostgreSQL. A protected local keyring file supplies:

- an active key identifier;
- one or more 32-byte AES keys encoded as base64.

On POSIX systems MON refuses a keyring file that grants any group or other permissions. The
keyring file is an initial deployment boundary, not a claim that local files are equivalent to
a managed KMS/HSM. A future key-provider adapter may use a cloud KMS or HSM without changing
the database record format or connector reference model.

Old keys must remain in the keyring until every record encrypted with them has been re-keyed.
Missing keys fail closed.

### Credential references

`EnforcementPoint` carries an optional `credential_ref`. Generic enforcement-point
`attributes` reject common inline credential keys such as passwords, API keys, bearer/auth
tokens, client secrets, private keys, and generic credential fields, including nested
dictionaries/lists.

The reference is safe metadata. It may appear in the operator API and enforcement graph.
Secret plaintext is not exposed by a MON HTTP endpoint.

Connector code resolves a credential through the vault using the already scoped
`tenant_id`, `site_id`, and `credential_ref`.

### Provisioning path

The host-side `mon-connector-secret` command is the initial provisioning surface.

- database connectivity comes from `MON_DATABASE_URL`, avoiding a database password in the
  command arguments;
- the secret value is accepted only from stdin and interactive terminal input is refused;
- the keyring path comes from `MON_CONNECTOR_SECRET_KEYRING_FILE` or a non-secret file-path
  option;
- put, re-key, and delete operations require an explicit actor identifier;
- command output contains metadata only.

Put/re-key/delete operations write immutable audit records containing only the secret
identifier, actor, action, outcome, and encryption key identifiers. Plaintext is excluded.

The encrypted-secret mutation and its audit record use one database transaction.

### Multi-tenant isolation

Migration 0009 enables and forces PostgreSQL RLS on `connector_secrets`, using the same
transaction-local tenant/site scope defined by ADR 0040. The production application/CLI role
must remain non-superuser and must not have `BYPASSRLS`.

## Security boundary

This design protects connector plaintext from ordinary database reads, backups, browser/API
responses, generic MON JSON state, and accidental logging through model representation.

It does not protect against an attacker who simultaneously obtains the encrypted database and
the external keyring, nor against a compromised process while that process is legitimately
resolving a credential. It also does not claim hardware-backed key custody. Those require
deployment-specific KMS/HSM/process-isolation controls.

MON does not log, return, or audit resolved plaintext.

## Consequences

- Production connectors can reference credentials without embedding them in enforcement
  metadata.
- Database compromise alone does not reveal connector plaintext.
- Ciphertext swapping across tenant/site/secret scope fails AEAD authentication.
- Key rotation is explicit and can overlap old/new keys.
- Key loss is operationally destructive, so keyring backup/recovery is a release/deployment
  responsibility.
- A production connector still requires its own sandbox/VM certification and least-privilege
  vendor credential design before release.
