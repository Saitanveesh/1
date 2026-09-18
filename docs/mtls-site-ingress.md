# mTLS site-ingress development profile

The ordinary development stack starts the control plane and PostgreSQL:

```bash
docker compose up --build
```

The site mTLS gateway is opt-in because it requires certificate material. Put these files
in a directory outside source control:

- `server.pem` - TLS server certificate for the ingress endpoint
- `server-key.pem` - matching server private key
- `site-ca.pem` - MON site CA certificate used to verify site client certificates

Then set `MON_MTLS_CERT_DIR` to that directory and start the profile:

```bash
MON_MTLS_CERT_DIR=/secure/mon-certs docker compose --profile mtls up --build
```

The gateway listens on 8443 and forwards verified event batches to the internal control
plane. Do not expose the internal control-plane site-ingestion path as a replacement for
the gateway in production.
