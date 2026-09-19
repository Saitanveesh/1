# Control-plane authentication

MON validates JWT bearer tokens before applying tenant/site RBAC.

## Production key configuration

Preferred production configuration:

- MON_AUTH_ISSUER
- MON_AUTH_AUDIENCE
- MON_AUTH_JWKS_FILE

The JWKS file must contain public RSA signing keys with unique kid values. Tokens must use RS256
and carry a kid header. Keep the retiring and successor public keys in the set during the issuer
overlap window, then atomically replace the file to remove the retiring key.

MON watches the file identity, size, and modification timestamp and reloads it without process
restart. The complete replacement file is validated before use. If a changed file is malformed or
unreadable, authentication becomes unavailable rather than continuing with stale trust.

Use an atomic rename/replace from the same filesystem. Do not rewrite the live file incrementally.

MON_AUTH_JWKS_JSON is available for deployments that inject the complete public JWKS document as
an environment value. It is static for the lifetime of the cached authenticator.

## Compatibility mode

MON_AUTH_PUBLIC_KEY_FILE or MON_AUTH_PUBLIC_KEY_PEM configures one RSA public key. This mode is
kept for small deployments and tests, but it does not provide overlapping key rotation.

JWKS and single-key settings are mutually exclusive.

## Trust boundary

The repository intentionally does not fetch a remote JWKS URL during authentication. A deployment
may synchronize an identity provider's JWKS into the local protected file through its secret or
configuration system, but MON's request path validates only locally materialized trust.

Private RSA key material and symmetric JWKS keys are rejected. The control plane needs verification
keys only.
