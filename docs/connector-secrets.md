# Connector secret operations

MON connector credentials are encrypted before they are stored in PostgreSQL. They are not
configured in `EnforcementPoint.attributes` and there is no HTTP endpoint that returns secret
plaintext.

## Keyring

The initial key provider is a protected JSON file:

```json
{
  "active_key_id": "connector-2026-09",
  "keys": {
    "connector-2026-09": "<base64 of exactly 32 random bytes>"
  }
}
```

On POSIX systems the file must not be readable, writable, or executable by group or others.
Use deployment secret tooling to materialize it with mode `0600`. Do not commit it to the
repository or bake it into an image.

Keep a previous key in the `keys` object while records encrypted with that key still exist.
Set `active_key_id` to the successor, re-key records, verify connector operation, and only
then remove the retired key.

## Provisioning

Set a scoped non-`BYPASSRLS` database credential in `MON_DATABASE_URL` and the protected
keyring path in `MON_CONNECTOR_SECRET_KEYRING_FILE`.

Store a credential from a protected file or secret-manager pipe:

```bash
mon-connector-secret put \
  --tenant tenant-a \
  --site site-1 \
  --secret-id edge-firewall-production \
  --actor deployment-admin \
  < /run/secrets/firewall-api-token
```

The command refuses interactive terminal secret input. It prints metadata only.

To re-encrypt an existing record with the keyring's current active key:

```bash
mon-connector-secret rotate \
  --tenant tenant-a \
  --site site-1 \
  --secret-id edge-firewall-production \
  --actor deployment-admin
```

Metadata inspection does not decrypt or print the credential:

```bash
mon-connector-secret metadata \
  --tenant tenant-a \
  --site site-1 \
  --secret-id edge-firewall-production
```

Deletion removes the encrypted record and writes a non-secret audit event:

```bash
mon-connector-secret delete \
  --tenant tenant-a \
  --site site-1 \
  --secret-id edge-firewall-production \
  --actor deployment-admin
```

## Enforcement-point reference

An enforcement point refers to the record by identifier:

```json
{
  "enforcement_point_id": "edge-fw-1",
  "tenant_id": "tenant-a",
  "site_id": "site-1",
  "kind": "FIREWALL",
  "vendor": "example",
  "capabilities": ["BLOCK_IP"],
  "credential_ref": "edge-firewall-production",
  "attributes": {
    "endpoint": "https://firewall.example.internal"
  }
}
```

Putting `password`, `api_key`, `api_token`, `client_secret`, `private_key`, or other
recognized credential fields inside enforcement-point attributes is rejected.

The current repository still has no production firewall/NAC/cloud connector enabled by
default. The vault establishes credential custody before those adapters are introduced.
