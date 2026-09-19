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

The gateway listens on 8443 and forwards verified site traffic to the internal control
plane. The production telemetry route is POST /api/v1/fabric/events. The gateway parses the
FabricEnvelope, requires its tenant/site scope to match the verified site certificate, and
then forwards the exact raw envelope bytes with the existing bearer authorization token.

The older event-batch route remains available for migration/compatibility. Do not expose the
internal control-plane site-ingestion paths as a replacement for the gateway in production.
