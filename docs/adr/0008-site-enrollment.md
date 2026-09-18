# ADR 0008: Site enrollment and client-certificate identity

Status: Accepted

## Decision

MON site controllers generate their private key locally and enroll by sending only a
certificate signing request plus a one-time bootstrap token to the control plane.

Enrollment tokens are random credentials whose plaintext is returned only at issuance.
The server stores only a SHA-256 hash. Tokens have a bounded lifetime and are consumed
atomically once.

The MON site CA issues short-lived TLS client certificates with clientAuth EKU and a
tenant/site SPIFFE-style URI in the SAN. Site identity metadata and certificate
fingerprints are durable control-plane state.

The site sender can use a client TLS context and a bearer service token simultaneously.
Until server-side mTLS peer-certificate enforcement is introduced at the trusted ingress,
JWT authorization remains the application-layer authorization mechanism.

## Trust boundary

A client certificate being issued is not, by itself, proof that FastAPI received and
validated that certificate. Production mTLS enforcement must occur at a trusted TLS
termination boundary that verifies the MON site CA and forwards a verified identity to
the application over a protected channel, or at a dedicated ingestion listener that
directly receives TLS peer-certificate state.

MON must never trust arbitrary public client-certificate headers.

## Key handling

The site private key is never uploaded to the control plane. Deployments should protect
the key using operating-system ACLs and, where available, TPM/HSM-backed storage.
