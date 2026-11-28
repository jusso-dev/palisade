# palisade-server

The central management server: policy distribution, approvals, inventory and event storage.

**Status:** process skeleton with a database foundation. The binary starts, loads and validates
its configuration, serves TLS on separate admin, agent and metrics listeners, answers liveness and
readiness probes, and shuts down gracefully. It connects to Postgres, applies its embedded
migrations, and isolates tenants with row-level security (see [Database](#database)). It has no
agent or API functionality yet. Work is tracked in
[#126](https://github.com/jusso-dev/palisade/issues/126) and
[#127](https://github.com/jusso-dev/palisade/issues/127) (epic
[#10](https://github.com/jusso-dev/palisade/issues/10)).

## Commands

```text
palisade-server serve         --config <PATH>   # run until SIGTERM or Ctrl-C
palisade-server check-config  --config <PATH>   # validate, then print the effective config
palisade-server migrate up      --config <PATH> # apply pending migrations, then verify
palisade-server migrate status  --config <PATH> # applied vs embedded migrations, as JSON
palisade-server migrate verify  --config <PATH> # checksums and row-level security checks
palisade-server version
```

`--config` can also come from `PALISADE_CONFIG`. Exit codes: `0` success (including a
completed shutdown), `1` runtime failure, `2` invalid configuration or command line. `migrate
status` exits `3` when migrations are pending.

`check-config` runs every check `serve` runs before it binds a socket: the TOML and environment
overrides, value ranges, the certificate chain and private key, the agent CA bundle, the TLS
policy, the database password files and CA file, the refused `PG*` variables (see
[Database](#database)), and that each `public_url` host is a subject alternative name (DNS or IP) of the server
certificate. It reports every problem at once, prints placement warnings (see
[Overlay deployments](#overlay-deployments)), and prints the effective configuration as JSON
with secret files shown by path only.

## Configuration

A TOML file; [`config/server.example.toml`](config/server.example.toml) documents every key.
Unknown keys are errors. Relative paths resolve against the directory of the file.

Every key can be overridden by an environment variable: `PALISADE_` plus the key path in upper
case, with `__` (two underscores) between levels. For example `PALISADE_LISTEN__ADMIN__PORT=9443`
or `PALISADE_TLS__KEY_FILE=/run/secrets/server.key`. Unknown `PALISADE_*` variables are reported
as warnings and ignored, so variables meant for other Palisade components do not stop the server.

| Key | Default | Notes |
|---|---|---|
| `deployment.profile` | `standard` | `standard` or `overlay` |
| `tls.cert_file` | required | PEM chain, leaf first |
| `tls.key_file` | required | PEM key (PKCS#8, PKCS#1 or SEC1). A secret file, see below |
| `tls.min_version` | `1.2` | `1.2` or `1.3`. TLS 1.3 is always preferred |
| `tls.profile` | `default` | `default` or `asd-strict`, see [TLS](#tls) |
| `listen.<name>.bind` | required (`127.0.0.1` for metrics) | An IP address, or a network interface name |
| `listen.<name>.port` | required (`9464` for metrics) | |
| `listen.<name>.public_url` | none | `https` URL clients use; checked against the certificate. Not on metrics |
| `listen.<name>.body_limit_bytes` | admin 16 MiB, agent 8 MiB, metrics 64 KiB | Up to 1 GiB |
| `listen.<name>.request_timeout_secs` | `30` | 1 to 3600 |
| `listen.<name>.max_connections` | admin and agent 4096, metrics 64 | |
| `listen.agent.client_ca_file` | required | CA bundle that agent client certificates must chain to |
| `shutdown.grace_secs` | `30` | Up to 3600 |
| `log.level` | `info` | `error`, `warn`, `info`, `debug`, `trace` |
| `database.host` | required if `[database]` is present | Host name or IP address |
| `database.port` | `5432` | |
| `database.name` | required | Database name |
| `database.user` | required | The **runtime** role. Must not own the schema or bypass RLS |
| `database.password_file` | required | A secret file holding the runtime role's password |
| `database.tls` | `verify-full` | `verify-full`, `verify-ca`, `require` or `disable`. The last two warn |
| `database.ca_file` | none | Extra trusted CA certificates (PEM). Only with `verify-*` |
| `database.max_connections` | `16` | Runtime pool size, 1 to 1000 |
| `database.connect_timeout_secs` | `5` | 1 to 300 |
| `database.auto_migrate` | on if `[database.migration]` is set | Apply pending migrations at start |
| `database.migration.user` | none | The **migration** role, which owns the schema |
| `database.migration.password_file` | none | A secret file holding its password |

`<name>` is `admin` (console, REST API, SSO callbacks), `agent` (agent traffic) or `metrics`
(probes with full detail, and later the metrics exposition). `admin` and `agent` are required.
`metrics` is optional; it is enabled by its section or by any `PALISADE_LISTEN__METRICS__*`
variable. Two listeners may not share a port on the same address (or on a wildcard of the same
address family); serving every surface on one port with path routing is not supported yet.

### Secret files

Secrets are only ever given as file paths, never as values, so the configuration file, the
environment, `check-config` output and the logs never contain them. The secrets are `tls.key_file`
and the database password files. It must be a regular file of at most 64 KiB, and on Unix it must not grant any
access to the group or others (`chmod 600` or stricter); otherwise the server refuses to start.
The database password files (`database.password_file`, `database.migration.password_file`) follow
the same rules, with a limit of 4 KiB; a trailing newline is not part of the password.
Its contents are held in zeroising buffers while loading, and error messages name the path and
the problem, never any content. Windows ACL checks, a redaction layer for log fields, and other
secret kinds are part of [#227](https://github.com/jusso-dev/palisade/issues/227).

## TLS

Every listener is TLS only; there is no plaintext listener and no option to add one. TLS is
provided by `rustls` with the `ring` provider
([ADR 0008](../../docs/adr/0008-cryptographic-algorithms.md)), cut down to an explicit
allowlist so a future default change in `rustls` cannot widen it:

| Profile | TLS 1.3 suites | TLS 1.2 suites | Key exchange |
|---|---|---|---|
| `default` | AES-256-GCM-SHA384, AES-128-GCM-SHA256 | ECDHE-ECDSA and ECDHE-RSA with AES-256-GCM-SHA384 or AES-128-GCM-SHA256 | X25519, P-256, P-384 |
| `asd-strict` | AES-256-GCM-SHA384 | ECDHE-ECDSA and ECDHE-RSA with AES-256-GCM-SHA384 | P-384 |

ChaCha20-Poly1305 is excluded. TLS 1.0 and 1.1 are not implemented by `rustls`. TLS 1.2 requires
the extended master secret extension, and the server's suite order is used. ALPN offers `h2` and
`http/1.1`.

The agent listener requires a client certificate that chains to `listen.agent.client_ca_file`;
a handshake without one fails. Matching the certificate to an enrolled device and checking
revocation is enrolment work ([#223](https://github.com/jusso-dev/palisade/issues/223)).

The certificate and key are read once at start. Hot reload is part of
[#224](https://github.com/jusso-dev/palisade/issues/224).

## Listeners and binding

`bind` takes an IP address (`127.0.0.1`, `100.64.0.7`, `::1`, `[fd7a::7]`, or `0.0.0.0` / `::`
for every interface) or the name of a network interface (for example `overlay0`; on Windows the
interface's friendly name). An interface binds every address it has. IPv6 sockets are always
IPv6-only, so `::` never silently covers IPv4 too.

Each listener has a supervisor that keeps it bound:

- An address that cannot be bound yet (an interface that is not up, an address not assigned yet,
  a port in use) is retried with exponential backoff from 1 s to 30 s. Readiness reports
  `listener_unbound:<name>` until every address is bound. This covers an overlay interface that
  comes up after the server at boot.
- A named interface is re-resolved every 5 s. New addresses are bound; addresses that vanish stop
  accepting.

Connections: the TLS handshake must finish within 10 s. The protocol follows ALPN: a connection
that negotiated `h2` is served as HTTP/2 only, and any other (including one with no ALPN) as
HTTP/1.1 only, so a client cannot switch protocols by sending another preface. The first request
must arrive within 30 s of the handshake, whatever the protocol, and each later HTTP/1.1 request
head within 30 s of the previous response; otherwise the connection is closed, so an idle or
stalled client cannot hold a connection slot. HTTP/1.1 request heads are limited to 64 KiB.
HTTP/2 allows 128 concurrent streams and 64 KiB of headers per request, with keep-alive pings.
A listener serves at most `max_connections` connections; a connection is accepted before it takes
a slot, so a socket with no clients never holds one, and while every slot is taken further
clients wait in the TCP backlog.

## HTTP stack

Every listener's router runs inside this middleware stack (outermost first):

1. **Request ID.** A client-supplied `Palisade-Request-Id` of 1 to 64 characters from
   `A-Z a-z 0-9 . _ : -` is kept; anything else is replaced by 128 random bits in hex. The ID is
   echoed on every response.
2. **Errors as problem details.** Every 4xx and 5xx response is an RFC 9457
   `application/problem+json` document with `type`
   (`https://palisade.dev/problems/<slug>`), `title`, `status`, `detail`, `instance`
   (`urn:palisade:request:<id>`) and `request_id`. Error bodies from inside the stack are
   replaced, so they cannot leak internals; only the `Allow`, `Retry-After` and
   `WWW-Authenticate` headers are kept. A 5xx `detail` tells the client to re-read before
   retrying a change. Errors that hyper produces before a request reaches the router (a malformed
   request line, oversized headers) are hyper's own minimal responses.
3. **Trace.** One span per request with `request_id`, `listener`, `method`, the matched route
   template (never the raw path or query) and `peer`, and one log line per response with
   `status` and `latency_ms`.
4. **Panic guard.** A panicking handler becomes a 500 problem. The panic message goes to the log.
5. **Timeout.** A handler still running after `request_timeout_secs` is cancelled with a 503
   problem.
6. **Body limit.** A body over `body_limit_bytes` gets a 413 problem, whether the size is
   declared in `Content-Length` or discovered while streaming.

Every response also carries `X-Content-Type-Options: nosniff`.

## Probes

Every listener serves:

- `GET /healthz`: liveness. `200 {"status":"alive"}` while the process can serve requests.
- `GET /readyz`: readiness. `200` when every listener is bound on every wanted address and the
  server is not shutting down; otherwise a `503` problem (`type` ending `not-ready`). On the
  admin and agent listeners the body carries only the overall status. On the metrics listener
  (loopback by default) it also lists the indicators:

| Indicator | Meaning | Readiness |
|---|---|---|
| `listener_unbound:<name>` | An address of the listener is not bound yet | 503 |
| `public_exposure:<name>` | `deployment.profile = "overlay"` and the listener is reachable on a public address | 200, status `degraded` |
| `shutting_down` | Shutdown has started | 503 |
| `database_down` | `[database]` is configured and the runtime role cannot reach it (also before the first check) | 503 |
| `database_schema:<verdict>` | The schema is `behind` (pending migrations), `newer` than this binary, or `damaged` | 503 |
| `database_role_unsafe` | The runtime role, or any role it is a member of, is a superuser, has `BYPASSRLS`, or owns or can create objects in the schema; or it is not in `palisade_runtime` | 503 |

The database is checked every 5 seconds. Job-runner readiness joins this list with #126.

## Database

Postgres 16 or later, through `sqlx` ([ADR 0006](../../docs/adr/0006-server-database.md)).
Without a `[database]` section the server runs without one, as before, and logs a warning.

**Roles.** Two logins, never the same role:

- The **migration role** owns the database, the `palisade` schema and every table. Only
  `migrate up` and `auto_migrate` use it.
- The **runtime role** serves every request. It owns nothing, is `NOSUPERUSER NOBYPASSRLS`, and
  gets its table privileges through the `palisade_runtime` group role, which the migrations
  grant to. These properties are checked through role membership too, because a role can
  `SET ROLE` to any role it is a member of: no role the runtime login can reach may be a
  superuser, have `BYPASSRLS`, or own the schema or any table, function or type in it (an owner
  of `palisade.current_tenant_ids()` could replace it). `serve` refuses to start, and readiness
  reports `database_role_unsafe`, if any check fails.

[`sql/bootstrap.sql`](sql/bootstrap.sql) creates the three roles and the database; run it once as
a database administrator with `psql` (the file shows the command), then set the two passwords
with `\password`. `palisade-server` never needs a superuser.

**Migrations.** Forward-only numbered SQL files in [`migrations/`](migrations/), embedded in the
binary with `sqlx::migrate!`. Each runs in a transaction, as the migration role. Before anything
is created, `migrate up` checks that role: not a superuser, not linked to `palisade_runtime` by
membership in either direction, and the owner of the `palisade` schema once it exists. A run as
the wrong role changes nothing. The history
lives in `palisade._sqlx_migrations` with a SHA-384 checksum per file, so an edited migration is a
hard error. At start, `serve` refuses a database whose schema is newer than the binary, and with
`auto_migrate` applies pending migrations first; otherwise it starts not ready until someone runs
`migrate up`. `serve` also refuses a damaged schema. `migrate verify` also checks the structure that ADR 0006 requires: every table with
a `tenant_id` column (and the tenant table) has row-level security enabled and forced and has a
policy and `tenant_id uuid NOT NULL`, every foreign key between tenant-owned tables includes
`tenant_id`, and no role a `palisade_runtime` login can act as owns anything in the schema or is
a superuser or `BYPASSRLS`. New migrations must stay forward-only and avoid long table rewrites
(expand/contract).

**Tables so far.** `tenant` (a tree with one `root`, `organisation` and `template` kinds, a
`settings` object) and `computer_group` (a tree per tenant). Each has `created_at`, `updated_at`
and `revision`, maintained by a trigger: inserts start at revision 1 and every update adds 1, so
a client can use the revision for optimistic concurrency (#185). A row's `id` and `tenant_id`
never change. The rest of the schema arrives with the issues that use it.

**Tenant isolation.** Every tenant-owned table has `tenant_id uuid NOT NULL`, `FORCE ROW LEVEL
SECURITY` (the policies apply to the table owner too), and a policy
`tenant_id = ANY (palisade.current_tenant_ids())`, for reads and writes. The function reads the
`palisade.tenant_ids` setting; when it is unset or empty, no rows match. The only way the server
code runs a tenant-scoped query is `Database::tenant_tx(scope)`, which begins a transaction and
sets the scope with `set_config(..., true)`, the function form of `SET LOCAL`. The scope ends with
the transaction, so a pooled connection never carries it to the next request. Foreign keys
between tenant-owned tables include `tenant_id`, so a row can never reference another tenant's
row.

**What row-level security does and does not protect.** It stops a bug in a handler (a missing
`WHERE`, a wrong ID) from reading or changing another tenant's rows: the database filters every
query, whatever the code asks. The runtime role cannot turn it off: it does not own the tables, so
it cannot `DISABLE` or `NO FORCE` row-level security or change the policies, and with
`row_security = off` a filtered query fails rather than returning everything. It does **not**
protect against a compromised server process. That process holds the runtime role and chooses
the scope itself, so it can ask for any tenant (threat model AC-08). The integration tests
demonstrate both sides.

**Environment.** The Postgres client library reads some `PG*` environment variables. The server
refuses to start, and `migrate` refuses to run, while `PGPASSWORD`, `PGPASSFILE`, `PGOPTIONS`,
`PGSSLKEY`, `PGSSLCERT`, `PGSSLMODE`, `PGSSLROOTCERT` or `PGHOSTADDR` is set, because these would
override the configuration (a password outside a `*_file`, or a session setting such as
`row_security`).

**Queries.** Fixed SQL strings with typed bind parameters only. Compile-time-checked queries
(`query!`) need a live database or committed offline metadata; they are not used yet, and adopting
them, with a lint against string-built SQL, is part of #229.

## Overlay deployments

For a fleet reachable only through a private overlay network
([#239](https://github.com/jusso-dev/palisade/issues/239)), bind the admin and agent listeners
to the overlay interface or address, keep metrics on loopback, and set
`deployment.profile = "overlay"`:

```toml
[deployment]
profile = "overlay"

[listen.admin]
bind = "overlay0"              # or the overlay address, e.g. "100.64.0.7"
port = 8443
public_url = "https://palisade-server.overlay.example:8443"

[listen.agent]
bind = "overlay0"
port = 8444
public_url = "https://palisade-server.overlay.example:8444"
client_ca_file = "tls/agent-ca.crt"

[listen.metrics]
bind = "127.0.0.1"
```

Under the overlay profile, `check-config` and `serve` warn when a listener binds every interface,
is reachable on a public address, or (for metrics) is not on loopback. While the server runs,
public reachability is also reported as `public_exposure:<name>` in readiness. "Public" means
anything outside loopback, RFC 1918, the RFC 6598 shared space `100.64.0.0/10`, link-local,
IPv6 unique-local `fc00::/7`, and the documentation, benchmarking and reserved ranges.

The certificate must name every `public_url` host (the overlay DNS name or overlay IP) as a SAN;
`check-config` fails otherwise. The overlay is transport only: TLS and client certificates stay
mandatory over it.

## Logs

`serve` writes one JSON object per line to standard error: `timestamp`, `level`, `target`,
`fields` (including `message`), `span` (the current span) and `spans` (every enclosing span, so
the request span's fields stay on the line when a handler opens a child span). The level comes
from `log.level`. No secret value is passed to the logger: the configuration holds only secret
paths, and the secret reader's errors never contain file contents. Secrets read from files are
held in `secret::Secret`, which is wiped on drop and prints as `[REDACTED]` in `Debug` and
`Display`. As a second line of defence, every log line is redacted on its way out
(`redact`, #227): any field, in the event or in any span, whose name has a segment such as
`password`, `secret`, `token`, `key`, `authorization`, `cookie` or `code` is replaced by
`[REDACTED]` (names ending in `file` or `path`, such as `key_file`, are kept, since they hold
paths), and admin API tokens (`pal_<env>_<id>_` keeps its prefix), `Bearer` and `Basic`
credentials and PEM private key bodies are masked wherever they appear. Tenant and principal fields
join the request span with the API work.

## Shutdown

On SIGTERM or SIGINT (Ctrl-C), or on Windows Ctrl-C, Ctrl-Break and the console close, logoff
and shutdown events (the handlers are registered before any socket is bound, so an early signal is
never lost): readiness fails, every listener stops accepting, and open connections are asked to
finish their in-flight requests and close (HTTP/1.1 after the current response, HTTP/2 with
GOAWAY). If any remain after `shutdown.grace_secs`, they are dropped. The process exits `0`
either way. A second signal during the drain exits `1` immediately.

## Not here yet

Tracked in [#126](https://github.com/jusso-dev/palisade/issues/126) unless noted:
`create-admin`, `backup` and `restore` subcommands (also
[#138](https://github.com/jusso-dev/palisade/issues/138)); `/version` with git SHA and schema
version; single-port mode; compression, CORS, rate-limit, auth and tenant layers;
the metrics exposition and OTLP; runtime log-level changes; clock-skew health; the job runner
and scheduler; relay role. Elsewhere: the rest of the schema, secrets at rest, soft delete, retention and
partitioning ([#127](https://github.com/jusso-dev/palisade/issues/127) and the issues that own
each table), the audit log ([#132](https://github.com/jusso-dev/palisade/issues/132)), enrolment and device certificate
checks ([#223](https://github.com/jusso-dev/palisade/issues/223)), agent RPCs
([#62](https://github.com/jusso-dev/palisade/issues/62)), REST conventions
([#185](https://github.com/jusso-dev/palisade/issues/185)), certificate hot reload
([#224](https://github.com/jusso-dev/palisade/issues/224)), secrets hardening
([#227](https://github.com/jusso-dev/palisade/issues/227)), server hardening
([#229](https://github.com/jusso-dev/palisade/issues/229)).

## Allowed dependencies

`palisade-core`, `palisade-fileid`, `palisade-policy`, `palisade-proto`. The rules are enforced by
`cargo xtask check-deps`. None are used yet.

## Platform support

All platforms. Secret-file permission checks apply on Unix; SIGTERM handling is Unix-only, with
the console events above on Windows.

## Feature flags

None yet.

## Stability

Unstable and not published. Anything may change.
