# 0016. Server database, tenant isolation and tenant scope binding

- Status: accepted
- Date: 2026-11-23
- Deciders: Palisade maintainer

## Context

This ADR supersedes [ADR 0006](0006-server-database.md). It keeps that decision (Postgres through
`sqlx`, a shared schema with row-level security), but corrects what the decision guarantees.

ADR 0006 said that RLS means "a bug in the application layer still cannot cross tenants". That
is too strong. RLS compares each row with the tenant scope the server sets for the transaction.
It does not check that the scope is the right one for the caller. If an authorisation bug
resolves a tenant A request to tenant B, the server sets scope B, and RLS returns B's rows. The
same holds for SQL injection: injected SQL runs in the same session and could change the scope
setting. RLS protects against a query that forgets or gets wrong its tenant filter. It does not
protect against a wrong scope.

The rest of the context is unchanged. `palisade-server` (#10) stores tenants, groups, policies
and their version history, approvals, RBAC, inventory and a large volume of execution events. The
Essential Eight logging controls expect allowed and blocked events to stay searchable for at
least 12 months and to be protected from modification. The server is multi-tenant (#128), so one
tenant must never read or write another tenant's rows, whether through the API, the console or
the query language. Issue #127 holds the detailed schema work.

## Decision drivers

1. Tenant isolation that holds even when a query omits or mistypes its tenant filter.
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

Binding the scope to the caller (new):

1. **A database-enforced binding**, for example one database role per tenant selected with
   `SET ROLE`, or a signed scope token that a database function verifies. The database only
   ever talks to the server, never to the end caller. So the server still chooses the role or
   holds the signing key, and the same server bug that picks the wrong tenant picks the wrong
   role or signs the wrong token. Per-tenant roles also grow the catalogue with the tenant
   count, like option 2 above. This adds cost without adding an independent check.
2. **One audited scope-resolution point in the server, and a narrower stated guarantee.** RLS
   covers query mistakes. Scope resolution is kept small, in one place, and tested on its own.

## Decision

- **Postgres 16 or later, through `sqlx`**, with compile-time checked queries. The `SQLX_OFFLINE`
  query metadata is committed so CI builds without a live database (#127).
- **Migrations use `sqlx::migrate!`**, embedded in the binary, numbered and forward-only, with
  expand/contract for schema changes. A migration checksum mismatch is a hard error, and the
  server refuses to start against a schema newer than itself.
- **Tenancy is a shared schema with row-level `tenant_id` plus RLS.**
  - Every tenant-owned table has `tenant_id uuid not null` and an RLS policy keyed on a
    per-transaction setting that the server sets from the caller's resolved scope.
  - Tenant tables use `FORCE ROW LEVEL SECURITY`, so the policies apply even to the table owner.
    The policy expression fails closed: when the tenant setting is unset or empty, no rows match.
  - The server connects as a non-owner application role with `NOSUPERUSER`, `NOBYPASSRLS` and
    `NOCREATEROLE`. `NOBYPASSRLS` alone is not enough, because a superuser bypasses RLS whatever
    that attribute says. The application role is not a member of any role that is a superuser,
    has `BYPASSRLS` or owns tenant tables, so `SET ROLE` cannot leave RLS behind. At startup the
    server checks these attributes and memberships for its own role, and refuses to start if
    any is wrong. Migrations run as a separate owner role.
  - Foreign keys include `tenant_id`, so a row can never reference another tenant's row.
  - Shared rows (built-in permissions, seeded content) belong to a root tenant and are exposed
    through explicit read-only policies.
- **Scope binding: option 2.**
  - The scope is resolved in one function, from the authenticated principal only: the tenant
    bound to the device certificate (#223) for agents, and the RBAC grants of the signed-in user
    for the console and API (#128). It is never taken from a request path, parameter or body. A
    request that names a tenant is checked against the resolved scope, not used to set it.
  - The same function is the only code that writes the tenant setting, at the start of each
    transaction (#127). A CI check rejects any other code that writes it.
  - #127 has a cross-tenant test suite: two tenants, every API route, and each principal type,
    asserting that no response contains the other tenant's rows. For every attempted
    cross-tenant insert, update and delete, the suite also reads the stored rows directly and
    asserts that the other tenant's data is unchanged, because an empty
    response does not prove that nothing was written. The verifier uses a test-only role with
    `BYPASSRLS`, never the application role or the owner role, because `FORCE ROW LEVEL
    SECURITY` would otherwise hide a wrongly written row from it too.
- High-volume event tables are partitioned by month (#127).

## Consequences

### Positive

- Isolation does not depend on every query remembering a filter. A missing or wrong `WHERE`
  clause in a handler still cannot cross tenants.
- The code that can cross tenants is one small function, so review and tests can focus on it.
- Query typos and type mismatches fail at build time.
- One schema and one migration stream, whatever the tenant count.

### Negative

- A bug in scope resolution, or SQL injection, can still cross tenants. RLS does not catch
  either. The resolver and the parameterised-query rule carry that risk instead.
- RLS adds a per-query cost and makes query plans harder to read. Indexes must lead with
  `tenant_id`.
- Building with compile-time checks needs either a database or up-to-date offline metadata.
  Stale metadata fails CI until it is regenerated.
- Each connection must set the tenant scope at the start of every transaction. Pooling code has
  to make that impossible to forget (#127).

## Security impact

RLS moves the per-query tenant filter from handler code into the database, so a handler that
omits or mistypes its filter cannot read another tenant's policies, events or approval history.
RLS trusts the scope the server sets. The trust boundary for tenant isolation is therefore the
scope resolver, and the threat model (#219) records it as such. A resolver bug that maps a caller
to the wrong tenant crosses tenants, and RLS does not stop it. SQL injection is countered by
compile-time checked, parameterised queries, not by RLS, because injected SQL could change the
session's tenant setting. `NOSUPERUSER` and `NOBYPASSRLS` on the application role, with no route to a
role that bypasses RLS, mean a compromised server process cannot simply turn RLS off, but it can set any scope, so a compromised server is not
contained by RLS either. The owner role used for migrations is a separate secret (#227). Event
tables are the evidence trail for ISM-1660, so their append-only protection and retention live
in #127 and #229.

## Links

- Supersedes: 0006
- Issues #20, #127 (schema, migrations, isolation), #128 (multi-tenancy), #219 (threat model),
  #223 (device identity), #227 (secrets), #229 (server hardening). Epic #10.
