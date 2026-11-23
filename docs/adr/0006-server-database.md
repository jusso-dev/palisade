# 0006. Server database and tenant isolation

- Status: accepted
- Date: 2026-11-23
- Deciders: Palisade maintainer

## Context

`palisade-server` (#10) stores tenants, groups, policies and their version history, approvals,
RBAC, inventory and a large volume of execution events. The Essential Eight logging controls
expect allowed and blocked events to stay searchable for at least 12 months and to be protected
from modification. The server is multi-tenant (#128), so one tenant must never read or write
another tenant's rows, whether through the API, the console or the query language. Issue #127
holds the detailed schema work.

## Decision drivers

1. Tenant isolation that holds even when application code has a bug.
2. Relational integrity across policies, rules, groups, approvals and their history.
3. Query safety: SQL checked at build time, no string-built queries.
4. Forward-only, reviewable migrations that run automatically and idempotently.
5. Event volume: time-partitioned tables with retention.
6. One database a learner can run locally or in a container.

## Considered options

Database and access layer:

1. **Postgres with sqlx** (async, compile-time checked queries through `query!`/`query_as!`, with
   offline metadata for CI). Mature row-level security, partitioning and JSON support.
2. **Postgres with a full ORM.** Less SQL to write, but the generated SQL is harder to review,
   and RLS and partitioning still need raw SQL.
3. **An embedded or document store.** Simple to deploy, but no row-level security, weak
   relational integrity, and poor fit for 12-month searchable event retention.

Multi-tenancy:

1. **Shared schema, `tenant_id` on every row, enforced by Postgres row-level security (RLS).**
   One schema to migrate. Isolation is enforced by the database for every query.
2. **Schema per tenant.** Strong separation, but migrations run once per tenant, cross-tenant
   features (the tenant tree, global groups) need dynamic SQL, and the catalogue grows with the
   tenant count.
3. **Database per tenant.** Strongest separation, but the most operational cost, and it rules
   out the shared tenant tree in #128.
4. **Application-only filtering** (`WHERE tenant_id = $1` in code). Cheapest, but one missed
   filter leaks data.

## Decision

- **Postgres 16 or later, through `sqlx`**, with compile-time checked queries. The `SQLX_OFFLINE`
  query metadata is committed so CI builds without a live database (#127).
- **Migrations use `sqlx::migrate!`**, embedded in the binary, numbered and forward-only, with
  expand/contract for schema changes. A migration checksum mismatch is a hard error, and the
  server refuses to start against a schema newer than itself.
- **Tenancy is a shared schema with row-level `tenant_id` plus RLS.**
  - Every tenant-owned table has `tenant_id uuid not null` and an RLS policy keyed on a
    per-transaction setting that the server sets from the caller's resolved scope.
  - The server connects as a non-owner role with `NOBYPASSRLS`. Migrations run as a separate
    owner role.
  - Foreign keys include `tenant_id`, so a row can never reference another tenant's row.
  - Shared rows (built-in permissions, seeded content) belong to a root tenant and are exposed
    through explicit read-only policies.
- High-volume event tables are partitioned by month (#127).

## Consequences

### Positive

- Isolation does not depend on every query remembering a filter. A bug in the application layer
  still cannot cross tenants.
- Query typos and type mismatches fail at build time.
- One schema and one migration stream, whatever the tenant count.

### Negative

- RLS adds a per-query cost and makes query plans harder to read. Indexes must lead with
  `tenant_id`.
- Building with compile-time checks needs either a database or up-to-date offline metadata.
  Stale metadata fails CI until it is regenerated.
- Each connection must set the tenant scope at the start of every transaction. Pooling code has
  to make that impossible to forget (#127).

## Security impact

RLS moves tenant isolation from application code into the database, so an injection or
authorisation bug in one handler cannot read another tenant's policies, events or approval
history. `NOBYPASSRLS` on the application role means a compromised server process cannot simply
turn RLS off. The owner role used for migrations is a separate secret (#227). Compile-time
checked, parameterised queries remove string-built SQL as an injection vector. Event tables are
the evidence trail for ISM-1660, so their append-only protection and retention live in #127
and #229.

## Links

- Issues #20, #127 (schema, migrations, isolation), #128 (multi-tenancy), #227 (secrets),
  #229 (server hardening). Epic #10.
