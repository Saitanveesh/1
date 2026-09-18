# ADR 0007: Authentication and tenant/site authorization

Status: Accepted

## Decision

Every control-plane API except health requires an authenticated principal. MON validates
asymmetric JWTs against a configured public key, issuer and audience. Authentication
configuration fails closed; missing verifier configuration does not expose protected
routes.

The authenticated principal carries roles plus tenant and optional site scope. URLs and
request bodies do not grant scope by themselves.

Roles:

- platform_admin: cross-tenant view, configuration, response and ingestion
- tenant_admin: view, configuration and response inside one tenant
- soc_analyst: view and response inside one tenant
- viewer: read-only view
- site_controller: ingestion only, restricted to explicitly listed site IDs

## Live transport

WebSocket subscriptions use the same authenticated principal as REST. The tenant/site
query parameters select a scope the principal is already authorized to view; they do not
create authorization.

Browser sessions may use a secure same-origin `mon_session` cookie. Bearer JWTs are
also accepted for API clients and non-browser WebSocket clients.

## Token verification

The first implementation verifies RS256 JWTs using a configured PEM public key. It
requires signature, issuer, audience, expiry, issued-at and subject validation.

Production identity-provider integration should add rotating JWKS retrieval and key
rotation. Token issuance remains outside the MON API.

## Remaining work

Site-controller mTLS identity is separate from operator JWT authentication. Enrollment,
client certificate issuance and mTLS enforcement are the next identity milestone.
