# ADR 0040: PostgreSQL tenant/site row-level security

## Status

Accepted

## Context

MON already treats tenant and site scope as first-class application data and enforces scope
through authenticated principals plus repository method arguments. That application boundary
must remain mandatory, but a query defect in a multi-tenant SaaS service should not
automatically expose another tenant's rows.

ADR 0026 identified PostgreSQL row-level security (RLS) as a defense-in-depth target once the
repository could bind database work to an explicit tenant/site context.

## Decision

All current tenant/site-owned PostgreSQL control-plane tables are protected by forced RLS.

The application repository binds every normal scoped transaction to two transaction-local
PostgreSQL settings:

- `mon.tenant_id`
- `mon.site_id`

RLS policies require both stored columns to match those settings for reads and writes. The
tables use `FORCE ROW LEVEL SECURITY`, so the policy also applies to a table owner that does
not have PostgreSQL `BYPASSRLS` or superuser capability.

The protected tables include normalized events, processing/fabric receipts, findings,
incidents, assets, enforcement state, response state, audit records, site commands, site
identities, sensor fleet state, and sensor identities.

### Enrollment token lookup

Site and sensor enrollment begin with an opaque one-time token hash before MON knows the
tenant/site scope from durable state. Those two tables therefore use a narrower lookup
exception instead of disabling RLS.

The repository sets a transaction-local `mon.enrollment_token_hash` only for the exact hash
being presented. The RLS `USING` clause permits that exact row to be read. Any insert or
update must still satisfy the normal tenant/site `WITH CHECK` policy, so after reading a valid
token the repository binds the transaction to the token's durable tenant/site scope before it
marks the token used.

This is not a general cross-tenant bypass.

### Database role requirement

Production application connections must use a PostgreSQL role that is:

- not a superuser;
- not granted `BYPASSRLS`;
- not used to run schema migrations.

Migration/owner credentials remain separate operational credentials. Running the MON API as a
superuser would bypass PostgreSQL RLS and is explicitly unsupported for production.

CI creates a dedicated non-superuser, non-`BYPASSRLS` application role after migrations and
runs the PostgreSQL integration suite through that role.

### Transaction boundary

One explicit `DatabaseStore.transaction()` may bind to only one tenant/site. Attempting to
switch scope inside that transaction fails closed. Independent repository calls may use
different scopes because each call has its own database transaction.

Application authorization remains the primary decision boundary. RLS does not authorize a
principal; it only constrains database rows after the repository has selected a scope.

## Consequences

- An unscoped SQL query through the production application role sees no protected tenant rows.
- A scoped query cannot see rows from another tenant or site.
- Cross-scope inserts fail the RLS `WITH CHECK` policy.
- The full PostgreSQL integration suite now executes with RLS active instead of relying on the
  migration-owner role.
- Migrations and emergency database administration require a separate privileged role and
  must remain outside the runtime application credential.
- RLS reduces blast radius from repository/query defects but does not protect against a
  compromised database superuser or a compromised application process that deliberately
  changes its own transaction-local scope.
