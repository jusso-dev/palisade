//! The Postgres layer: connection pools, embedded migrations, the
//! schema-version check and the per-transaction tenant scope.
//!
//! ADR 0006 (`docs/adr/0006-server-database.md`) decides the model:
//! one shared schema, `tenant_id` on every tenant-owned row, and row-level
//! security (RLS) that the database enforces for every query. This module
//! supplies the pieces the rest of the server builds on:
//!
//! - [`Database::connect_runtime`]: the pool for the **runtime role**, the
//!   only login the server serves requests with. That role owns nothing and
//!   cannot bypass RLS. [`start`] refuses to start with a role that could,
//!   and readiness keeps checking.
//! - [`migrator`]: forward-only migrations from `migrations/`, embedded in
//!   the binary. They run as the separate **migration role**, which owns the
//!   schema ([`migrate_up`]).
//! - [`schema_state`]: compares the applied migrations with the embedded
//!   ones, so the server refuses to start against a schema newer than
//!   itself, and `migrate verify` reports checksum mismatches.
//! - [`TenantTx`]: the only way to run tenant-scoped queries. It begins a
//!   transaction and sets `palisade.tenant_ids` with `SET LOCAL` semantics
//!   before any query can run, so the scope never leaks to the next user of
//!   a pooled connection.
//!
//! Every query is a fixed SQL string with typed bind parameters. Nothing
//! here builds SQL from values.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use serde_json::{Value, json};
use sqlx::migrate::{MigrateError, Migrator};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use sqlx::types::Uuid;
use sqlx::{Connection as _, PgConnection, PgPool, PgTransaction};
use zeroize::Zeroizing;

use crate::config::{DatabaseSettings, DbLogin, DbTls};
use crate::health::{DatabaseHealth, Health};
use crate::secret::read_secret_file;
use crate::tls::read_certs;

/// The schema that holds every Palisade object, the migration history
/// included.
pub const SCHEMA: &str = "palisade";
/// The migration history table, schema-qualified.
const HISTORY_TABLE: &str = "palisade._sqlx_migrations";
/// The group role the runtime login must belong to.
pub const RUNTIME_GROUP: &str = "palisade_runtime";
/// The setting that holds the tenant scope of the current transaction.
pub const TENANT_SETTING: &str = "palisade.tenant_ids";
/// Largest password file accepted, in bytes.
const MAX_PASSWORD_BYTES: usize = 4096;
/// `application_name` reported to Postgres.
const APPLICATION_NAME: &str = "palisade-server";
/// Tenant IDs in one scope. A larger scope is a caller bug, not a tenant
/// tree (#128 resolves subtrees in the database).
pub const MAX_SCOPE: usize = 10_000;

/// Environment variables that the Postgres client library reads when it
/// builds connection options. Palisade sets every connection parameter from
/// its own configuration, so these are refused rather than silently mixed
/// in: a password or a TLS client key would bypass the `*_file` rule, and
/// `PGOPTIONS` could change session settings such as `row_security`.
pub const REFUSED_PG_ENV: &[&str] = &[
    "PGPASSWORD",
    "PGPASSFILE",
    "PGOPTIONS",
    "PGSSLKEY",
    "PGSSLCERT",
    "PGSSLMODE",
    "PGSSLROOTCERT",
    "PGHOSTADDR",
];

/// The embedded migrations, in version order, with the history table in
/// the `palisade` schema.
pub fn migrator() -> &'static Migrator {
    static MIGRATOR: LazyLock<Migrator> = LazyLock::new(|| {
        let mut m = sqlx::migrate!("./migrations");
        m.dangerous_set_table_name(HISTORY_TABLE);
        m.create_schema(SCHEMA);
        m
    });
    &MIGRATOR
}

/// A database error, already rendered for logs and operators. It never
/// contains a password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbError(pub String);

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DbError {}

impl From<sqlx::Error> for DbError {
    fn from(e: sqlx::Error) -> Self {
        Self(describe(&e))
    }
}

impl From<MigrateError> for DbError {
    fn from(e: MigrateError) -> Self {
        Self(match e {
            MigrateError::VersionMismatch(v) => format!(
                "migration {v} was applied with different contents than this binary embeds (checksum mismatch); the database or the binary has been changed"
            ),
            MigrateError::VersionMissing(v) => format!(
                "migration {v} is applied in the database but not embedded in this binary; the schema is newer than this binary"
            ),
            MigrateError::Dirty(v) => {
                format!("migration {v} failed part-way earlier; repair it by hand before retrying")
            }
            MigrateError::ExecuteMigration(inner, v) => {
                format!("migration {v} failed: {}", describe(&inner))
            }
            MigrateError::Execute(inner) => describe(&inner),
            other => other.to_string(),
        })
    }
}

/// A short description of a driver error. Database errors carry their
/// SQLSTATE, which is what operators search for.
fn describe(e: &sqlx::Error) -> String {
    match e {
        sqlx::Error::Database(d) => match d.code() {
            Some(code) => format!("database error {code}: {}", d.message()),
            None => format!("database error: {}", d.message()),
        },
        sqlx::Error::PoolTimedOut => "timed out waiting for a database connection".to_owned(),
        other => other.to_string(),
    }
}

/// Names of [`REFUSED_PG_ENV`] variables for which `is_set` is true.
pub fn refused_env(is_set: impl Fn(&str) -> bool) -> Vec<&'static str> {
    REFUSED_PG_ENV
        .iter()
        .copied()
        .filter(|n| is_set(n))
        .collect()
}

/// Fails if the process environment sets any [`REFUSED_PG_ENV`] variable.
pub fn check_pg_env() -> Result<(), DbError> {
    let found = refused_env(|n| std::env::var_os(n).is_some());
    if found.is_empty() {
        Ok(())
    } else {
        Err(DbError(format!(
            "unset {}: palisade-server takes every database setting from its configuration, and these would override it (passwords come only from *_file paths)",
            found.join(", ")
        )))
    }
}

/// Connection options for one login. Its `Debug` output leaves out the
/// password, which the driver's own type would print.
#[derive(Clone)]
pub struct ConnectOptions(PgConnectOptions);

impl fmt::Debug for ConnectOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectOptions")
            .field("host", &self.0.get_host())
            .field("port", &self.0.get_port())
            .field("user", &self.0.get_username())
            .field("database", &self.0.get_database())
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Connection options for one login. The password is read from its secret
/// file here and handed to the driver; it is never logged or returned. The
/// driver keeps its own copy for reconnecting, which is not zeroised (#227).
pub fn connect_options(
    settings: &DatabaseSettings,
    login: &DbLogin,
) -> Result<ConnectOptions, DbError> {
    check_pg_env()?;
    let password = read_secret_file(&login.password_file, MAX_PASSWORD_BYTES).map_err(DbError)?;
    let password = Zeroizing::new(
        std::str::from_utf8(&password)
            .map_err(|_| {
                DbError(format!(
                    "password file {} is not valid UTF-8",
                    login.password_file.display()
                ))
            })?
            // A trailing newline from `echo` or an editor is not part of
            // the password.
            .trim_end_matches(['\r', '\n'])
            .to_owned(),
    );
    if password.is_empty() {
        return Err(DbError(format!(
            "password file {} is empty",
            login.password_file.display()
        )));
    }
    let mut options = PgConnectOptions::new_without_pgpass()
        .host(&settings.host)
        .port(settings.port)
        .database(&settings.name)
        .username(&login.user)
        .password(&password)
        .application_name(APPLICATION_NAME)
        .ssl_mode(match settings.tls {
            DbTls::Disable => PgSslMode::Disable,
            DbTls::Require => PgSslMode::Require,
            DbTls::VerifyCa => PgSslMode::VerifyCa,
            DbTls::VerifyFull => PgSslMode::VerifyFull,
        });
    if let Some(ca) = &settings.ca_file {
        // The driver accepts a file with no certificates and falls back to
        // the OS roots alone, so check it first.
        read_certs(ca).map_err(|e| DbError(format!("database.ca_file: {e}")))?;
        options = options.ssl_root_cert(ca);
    }
    Ok(ConnectOptions(options))
}

/// Checks everything about the database configuration that can be checked
/// without connecting: the refused `PG*` variables, every password file,
/// and the CA file. `check-config` and `serve` run it before binding, so a
/// bad file is a configuration error (exit 2).
pub fn preflight(settings: &DatabaseSettings) -> Vec<String> {
    if let Err(e) = check_pg_env() {
        return vec![e.0];
    }
    let mut errors = Vec::new();
    let logins = std::iter::once(("database", &settings.runtime))
        .chain(settings.migration.iter().map(|m| ("database.migration", m)));
    for (key, login) in logins {
        if let Err(e) = connect_options(settings, login) {
            let e = if e.0.starts_with("database.ca_file") {
                e.0
            } else {
                format!("{key}.password_file: {e}")
            };
            if !errors.contains(&e) {
                errors.push(e);
            }
        }
    }
    errors
}

/// The runtime pool, with the checks that apply to it.
#[derive(Debug, Clone)]
pub struct Database {
    pool: PgPool,
    check_timeout: Duration,
}

impl Database {
    /// A pool for the runtime login. It connects lazily, so the server can
    /// start (and report the database as down) while Postgres is
    /// unreachable.
    pub fn connect_runtime(settings: &DatabaseSettings) -> Result<Self, DbError> {
        let options = connect_options(settings, &settings.runtime)?.0;
        let pool = PgPoolOptions::new()
            .max_connections(settings.max_connections)
            .acquire_timeout(settings.connect_timeout)
            .idle_timeout(Duration::from_secs(600))
            .test_before_acquire(true)
            .connect_lazy_with(options);
        Ok(Self {
            pool,
            check_timeout: settings.connect_timeout,
        })
    }

    /// The pool, for statements that are not tenant-scoped, such as the
    /// readiness check. Tenant-owned tables return no rows through it.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Begins a tenant-scoped transaction. See [`TenantTx`].
    pub async fn tenant_tx(&self, scope: &TenantScope) -> Result<TenantTx, DbError> {
        TenantTx::begin(&self.pool, scope).await
    }

    /// Closes every connection.
    pub async fn close(&self) {
        self.pool.close().await;
    }
}

/// Connection options for the migration login.
pub fn migration_options(settings: &DatabaseSettings) -> Result<ConnectOptions, DbError> {
    let Some(login) = &settings.migration else {
        return Err(DbError(
            "database.migration is not configured; migrations run as the schema owner, not the runtime role".to_owned(),
        ));
    };
    connect_options(settings, login)
}

/// Opens one connection, giving up after `timeout`.
pub async fn connect(options: &ConnectOptions, timeout: Duration) -> Result<PgConnection, DbError> {
    tokio::time::timeout(timeout, PgConnection::connect_with(&options.0))
        .await
        .map_err(|_| DbError("timed out connecting to the database".to_owned()))?
        .map_err(DbError::from)
}

/// Connects once with the migration login.
pub async fn connect_migration(settings: &DatabaseSettings) -> Result<PgConnection, DbError> {
    connect(&migration_options(settings)?, settings.connect_timeout).await
}

/// The tenants a transaction may see: the caller's resolved scope (#131).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantScope(Vec<Uuid>);

impl TenantScope {
    /// A scope of the given tenants, sorted and without duplicates. An empty
    /// scope is allowed and sees no tenant rows.
    pub fn new(tenants: impl IntoIterator<Item = Uuid>) -> Result<Self, DbError> {
        let mut ids: Vec<Uuid> = tenants.into_iter().collect();
        ids.sort_unstable();
        ids.dedup();
        if ids.len() > MAX_SCOPE {
            return Err(DbError(format!(
                "a tenant scope holds at most {MAX_SCOPE} tenants, got {}",
                ids.len()
            )));
        }
        Ok(Self(ids))
    }

    /// A scope of one tenant.
    pub fn one(tenant: Uuid) -> Self {
        Self(vec![tenant])
    }

    /// The tenants in the scope.
    pub fn tenants(&self) -> &[Uuid] {
        &self.0
    }

    /// The value of [`TENANT_SETTING`]: a Postgres `uuid[]` literal. UUIDs
    /// format as hex digits and hyphens only, so the literal needs no
    /// escaping; it is passed as a bound parameter anyway.
    fn setting_value(&self) -> String {
        let inner: Vec<String> = self.0.iter().map(Uuid::to_string).collect();
        format!("{{{}}}", inner.join(","))
    }
}

/// A transaction with the tenant scope set.
///
/// `begin` opens the transaction and runs
/// `set_config('palisade.tenant_ids', <scope>, true)` before handing it out.
/// The third argument makes the setting local to the transaction (the same
/// as `SET LOCAL`), so Postgres discards it at commit or rollback and the
/// pooled connection goes back without a scope. A transaction dropped
/// without [`commit`](Self::commit) rolls back.
///
/// RLS policies read the setting through `palisade.current_tenant_ids()`.
/// It is still the server that chooses the scope: RLS stops a handler bug
/// from crossing tenants, not a compromised server process (threat model
/// AC-08).
#[derive(Debug)]
pub struct TenantTx {
    tx: PgTransaction<'static>,
}

impl TenantTx {
    async fn begin(pool: &PgPool, scope: &TenantScope) -> Result<Self, DbError> {
        let mut tx = pool.begin().await?;
        sqlx::query("SELECT pg_catalog.set_config($1, $2, true)")
            .bind(TENANT_SETTING)
            .bind(scope.setting_value())
            .execute(&mut *tx)
            .await?;
        Ok(Self { tx })
    }

    /// The connection, for running queries inside the scope.
    pub fn conn(&mut self) -> &mut PgConnection {
        &mut self.tx
    }

    /// Commits. The scope ends with the transaction.
    pub async fn commit(self) -> Result<(), DbError> {
        self.tx.commit().await?;
        Ok(())
    }

    /// Rolls back. The scope ends with the transaction.
    pub async fn rollback(self) -> Result<(), DbError> {
        self.tx.rollback().await?;
        Ok(())
    }
}

/// What the runtime login is allowed to do, as Postgres reports it.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct RoleFacts {
    /// The login name.
    pub role_name: String,
    /// The login, or a role it is a member of, is a superuser.
    pub superuser: bool,
    /// The login, or a role it is a member of, has `BYPASSRLS`.
    pub bypass_rls: bool,
    /// Member of [`RUNTIME_GROUP`].
    pub in_runtime_group: bool,
    /// The login, or a role it is a member of, owns the `palisade` schema or
    /// a table, view, sequence, function or type in it. An owner can
    /// disable row-level security, change policies, or replace
    /// `palisade.current_tenant_ids()`.
    pub owns_objects: bool,
    /// The login, or a role it is a member of, can create objects in the
    /// `palisade` schema.
    pub can_create: bool,
}

impl RoleFacts {
    /// Problems that make the login unfit to be the runtime role.
    pub fn problems(&self) -> Vec<String> {
        let mut v = Vec::new();
        let user = &self.role_name;
        if self.superuser {
            v.push(format!(
                "role {user} is, or is a member of, a superuser, so row-level security does not apply to it"
            ));
        }
        if self.bypass_rls {
            v.push(format!(
                "role {user} has BYPASSRLS, directly or through a role it is a member of, so row-level security does not apply to it"
            ));
        }
        if self.owns_objects {
            v.push(format!(
                "role {user} owns objects in schema {SCHEMA}, directly or through a role it is a member of; an owner can disable row-level security, so serve requests with a separate non-owner role"
            ));
        }
        if self.can_create {
            v.push(format!("role {user} can create objects in schema {SCHEMA}"));
        }
        if !self.in_runtime_group {
            v.push(format!("role {user} is not a member of {RUNTIME_GROUP}"));
        }
        v
    }
}

/// Reads [`RoleFacts`] for the current login.
pub async fn role_facts(conn: &mut PgConnection) -> Result<RoleFacts, DbError> {
    let facts = sqlx::query_as::<_, RoleFacts>(
        // Every check follows role membership: a role the login can
        // `SET ROLE` to, or inherits from, counts as the login itself.
        // `pg_has_role(x, x, 'MEMBER')` is true, so the login is included.
        "WITH me AS (
             SELECT oid, rolname FROM pg_catalog.pg_roles WHERE rolname = current_user
         ),
         reach AS (
             SELECT o.oid, o.rolsuper, o.rolbypassrls
             FROM pg_catalog.pg_roles o, me
             WHERE pg_catalog.pg_has_role(me.oid, o.oid, 'MEMBER')
         )
         SELECT me.rolname::text AS role_name,
                EXISTS (SELECT 1 FROM reach WHERE rolsuper) AS superuser,
                EXISTS (SELECT 1 FROM reach WHERE rolbypassrls) AS bypass_rls,
                EXISTS (
                    SELECT 1 FROM pg_catalog.pg_roles g
                    WHERE g.rolname = $2 AND pg_catalog.pg_has_role(me.oid, g.oid, 'MEMBER')
                ) AS in_runtime_group,
                EXISTS (
                    SELECT 1 FROM pg_catalog.pg_namespace n
                    WHERE n.nspname = $1 AND n.nspowner IN (SELECT oid FROM reach)
                    UNION ALL
                    SELECT 1 FROM pg_catalog.pg_class c
                    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                    WHERE n.nspname = $1 AND c.relowner IN (SELECT oid FROM reach)
                    UNION ALL
                    SELECT 1 FROM pg_catalog.pg_proc f
                    JOIN pg_catalog.pg_namespace n ON n.oid = f.pronamespace
                    WHERE n.nspname = $1 AND f.proowner IN (SELECT oid FROM reach)
                    UNION ALL
                    SELECT 1 FROM pg_catalog.pg_type t
                    JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
                    WHERE n.nspname = $1 AND t.typowner IN (SELECT oid FROM reach)
                ) AS owns_objects,
                EXISTS (
                    SELECT 1 FROM pg_catalog.pg_namespace n, reach
                    WHERE n.nspname = $1
                      AND pg_catalog.has_schema_privilege(reach.oid, n.oid, 'CREATE')
                ) AS can_create
         FROM me",
    )
    .bind(SCHEMA)
    .bind(RUNTIME_GROUP)
    .fetch_one(&mut *conn)
    .await?;
    Ok(facts)
}

/// Fails unless the current login is fit to be the runtime role.
pub async fn check_runtime_role(conn: &mut PgConnection) -> Result<(), DbError> {
    let problems = role_facts(conn).await?.problems();
    if problems.is_empty() {
        Ok(())
    } else {
        Err(DbError(problems.join("; ")))
    }
}

/// One migration as embedded and as applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationStatus {
    /// The version number.
    pub version: i64,
    /// The description from the file name.
    pub description: String,
    /// Whether the binary embeds it.
    pub embedded: bool,
    /// Whether the database records it as applied successfully.
    pub applied: bool,
    /// Whether the database records it as failed part-way.
    pub failed: bool,
    /// Whether the applied checksum differs from the embedded one.
    pub checksum_mismatch: bool,
}

/// The schema compared with this binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaState {
    /// Every migration known to the binary or the database, by version.
    pub migrations: Vec<MigrationStatus>,
}

/// How the schema relates to the binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaVerdict {
    /// Every embedded migration is applied and matches.
    Current,
    /// Some embedded migrations are not applied yet.
    Behind,
    /// The database has a migration this binary does not embed.
    Newer,
    /// An applied migration's checksum differs, or one failed part-way.
    Damaged,
}

impl SchemaVerdict {
    /// The name used in output and readiness.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Behind => "behind",
            Self::Newer => "newer",
            Self::Damaged => "damaged",
        }
    }
}

impl SchemaState {
    /// The overall verdict. `Damaged` wins over `Newer`, which wins over
    /// `Behind`.
    pub fn verdict(&self) -> SchemaVerdict {
        let m = &self.migrations;
        if m.iter().any(|s| s.checksum_mismatch || s.failed) {
            SchemaVerdict::Damaged
        } else if m.iter().any(|s| s.applied && !s.embedded) {
            SchemaVerdict::Newer
        } else if m.iter().any(|s| s.embedded && !s.applied) {
            SchemaVerdict::Behind
        } else {
            SchemaVerdict::Current
        }
    }

    /// The highest applied version, if any.
    pub fn applied_version(&self) -> Option<i64> {
        self.migrations
            .iter()
            .filter(|s| s.applied)
            .map(|s| s.version)
            .max()
    }

    /// The highest embedded version.
    pub fn embedded_version(&self) -> Option<i64> {
        self.migrations
            .iter()
            .filter(|s| s.embedded)
            .map(|s| s.version)
            .max()
    }

    /// As JSON, for `migrate status` and `migrate verify`.
    pub fn to_json(&self) -> Value {
        json!({
            "verdict": self.verdict().as_str(),
            "applied_version": self.applied_version(),
            "embedded_version": self.embedded_version(),
            "migrations": self.migrations.iter().map(|m| json!({
                "version": m.version,
                "description": m.description,
                "embedded": m.embedded,
                "applied": m.applied,
                "failed": m.failed,
                "checksum_mismatch": m.checksum_mismatch,
            })).collect::<Vec<_>>(),
        })
    }
}

/// Compares the applied migrations with [`migrator`]. Works for the
/// migration role and the runtime role (which may read the history). A
/// database with no `palisade` schema yet has nothing applied.
pub async fn schema_state(conn: &mut PgConnection) -> Result<SchemaState, DbError> {
    let has_history: bool = sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1 FROM pg_catalog.pg_class c
             JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = $1 AND c.relname = '_sqlx_migrations'
         )",
    )
    .bind(SCHEMA)
    .fetch_one(&mut *conn)
    .await?;
    let applied: Vec<(i64, String, Vec<u8>, bool)> = if has_history {
        sqlx::query_as(
            "SELECT version, description, checksum, success
             FROM palisade._sqlx_migrations ORDER BY version",
        )
        .fetch_all(&mut *conn)
        .await?
    } else {
        Vec::new()
    };
    Ok(compare(migrator(), &applied))
}

/// The comparison behind [`schema_state`], without a database.
fn compare(migrator: &Migrator, applied: &[(i64, String, Vec<u8>, bool)]) -> SchemaState {
    let mut by_version: BTreeMap<i64, MigrationStatus> = BTreeMap::new();
    for m in migrator.iter() {
        if m.migration_type.is_down_migration() {
            continue;
        }
        by_version.insert(
            m.version,
            MigrationStatus {
                version: m.version,
                description: m.description.to_string(),
                embedded: true,
                applied: false,
                failed: false,
                checksum_mismatch: false,
            },
        );
    }
    for (version, description, checksum, success) in applied {
        let embedded = migrator.iter().find(|m| m.version == *version);
        let entry = by_version
            .entry(*version)
            .or_insert_with(|| MigrationStatus {
                version: *version,
                description: description.clone(),
                embedded: false,
                applied: false,
                failed: false,
                checksum_mismatch: false,
            });
        entry.applied = *success;
        entry.failed = !*success;
        entry.checksum_mismatch = embedded.is_some_and(|m| *m.checksum != **checksum);
    }
    SchemaState {
        migrations: by_version.into_values().collect(),
    }
}

/// What the migration login is, as Postgres reports it.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
struct MigrationRoleFacts {
    role_name: String,
    superuser: bool,
    runtime_group_exists: bool,
    /// The login can act as the runtime group, or the runtime group can act
    /// as the login. Either way the runtime role could own the schema.
    shares_runtime_group: bool,
    /// The owner of the `palisade` schema, if it exists.
    schema_owner: Option<String>,
    /// The login is the schema owner or a member of it.
    owns_schema: bool,
}

/// Fails unless the current login may run migrations: not a superuser,
/// `palisade_runtime` exists, the login and `palisade_runtime` are not
/// members of each other, and the login owns the `palisade` schema if it
/// already exists. It runs before anything is created, so a mistaken run as
/// another role changes nothing.
pub async fn check_migration_role(conn: &mut PgConnection) -> Result<(), DbError> {
    let f = sqlx::query_as::<_, MigrationRoleFacts>(
        "SELECT me.rolname::text AS role_name,
                me.rolsuper AS superuser,
                g.oid IS NOT NULL AS runtime_group_exists,
                COALESCE(pg_catalog.pg_has_role(me.oid, g.oid, 'MEMBER')
                      OR pg_catalog.pg_has_role(g.oid, me.oid, 'MEMBER'), false) AS shares_runtime_group,
                o.rolname::text AS schema_owner,
                COALESCE(pg_catalog.pg_has_role(me.oid, n.nspowner, 'MEMBER'), false) AS owns_schema
         FROM pg_catalog.pg_roles me
         LEFT JOIN pg_catalog.pg_roles g ON g.rolname = $2
         LEFT JOIN pg_catalog.pg_namespace n ON n.nspname = $1
         LEFT JOIN pg_catalog.pg_roles o ON o.oid = n.nspowner
         WHERE me.rolname = current_user",
    )
    .bind(SCHEMA)
    .bind(RUNTIME_GROUP)
    .fetch_one(&mut *conn)
    .await?;
    let user = &f.role_name;
    if f.superuser {
        return Err(DbError(format!(
            "role {user} is a superuser; run migrations as the schema owner role created by sql/bootstrap.sql"
        )));
    }
    if !f.runtime_group_exists {
        return Err(DbError(format!(
            "role {RUNTIME_GROUP} does not exist; run sql/bootstrap.sql first"
        )));
    }
    if f.shares_runtime_group {
        return Err(DbError(format!(
            "role {user} and {RUNTIME_GROUP} must not be members of each other"
        )));
    }
    if let Some(owner) = &f.schema_owner {
        if !f.owns_schema {
            return Err(DbError(format!(
                "schema {SCHEMA} is owned by {owner}, not {user}; run migrations as its owner"
            )));
        }
    }
    Ok(())
}

/// Applies every pending migration, as the migration role. Refuses a wrong
/// role, and a schema that is newer than this binary or damaged, before
/// changing anything.
pub async fn migrate_up(conn: &mut PgConnection) -> Result<SchemaState, DbError> {
    check_migration_role(conn).await?;
    let before = schema_state(conn).await?;
    match before.verdict() {
        SchemaVerdict::Newer => {
            return Err(DbError(
                "the database schema is newer than this binary; upgrade palisade-server instead"
                    .to_owned(),
            ));
        }
        SchemaVerdict::Damaged => {
            return Err(DbError(
                "the database schema does not match this binary's migrations; run `migrate verify` for details".to_owned(),
            ));
        }
        SchemaVerdict::Behind | SchemaVerdict::Current => {}
    }
    migrator().run_direct(None, conn, false).await?;
    schema_state(conn).await
}

/// Structural checks on the applied schema, beyond the checksums: every
/// table in the `palisade` schema that has a `tenant_id` column, or is the
/// tenant table, must have row-level security enabled and forced and at
/// least one policy; every foreign key from a tenant-owned table to another
/// tenant-owned table must include `tenant_id`; and the runtime group must
/// not own anything. Returns one message per problem.
pub async fn verify_structure(conn: &mut PgConnection) -> Result<Vec<String>, DbError> {
    let rows: Vec<(String, bool, bool, i64, bool)> = sqlx::query_as(
        "SELECT c.relname::text,
                c.relrowsecurity,
                c.relforcerowsecurity,
                (SELECT count(*) FROM pg_catalog.pg_policy p WHERE p.polrelid = c.oid),
                COALESCE((
                    SELECT a.attnotnull AND a.atttypid = 'pg_catalog.uuid'::pg_catalog.regtype
                    FROM pg_catalog.pg_attribute a
                    WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped
                ), true)
         FROM pg_catalog.pg_class c
         JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = $1 AND c.relkind IN ('r', 'p')
           AND (c.relname = 'tenant' OR EXISTS (
               SELECT 1 FROM pg_catalog.pg_attribute a
               WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped
           ))
         ORDER BY 1",
    )
    .bind(SCHEMA)
    .fetch_all(&mut *conn)
    .await?;
    let mut problems = Vec::new();
    for (table, enabled, forced, policies, tenant_id_ok) in &rows {
        if !tenant_id_ok {
            problems.push(format!(
                "table {SCHEMA}.{table}: tenant_id must be uuid NOT NULL"
            ));
        }
        if !enabled {
            problems.push(format!(
                "table {SCHEMA}.{table}: row-level security is not enabled"
            ));
        }
        if !forced {
            problems.push(format!(
                "table {SCHEMA}.{table}: row-level security is not forced"
            ));
        }
        if *policies == 0 {
            problems.push(format!(
                "table {SCHEMA}.{table}: has no row-level security policy"
            ));
        }
    }

    // Foreign keys between two tenant-owned tables (both have tenant_id)
    // must map tenant_id to tenant_id.
    let fks: Vec<(String, String)> = sqlx::query_as(
        "SELECT con.conname::text, src.relname::text
         FROM pg_catalog.pg_constraint con
         JOIN pg_catalog.pg_class src ON src.oid = con.conrelid
         JOIN pg_catalog.pg_class dst ON dst.oid = con.confrelid
         JOIN pg_catalog.pg_namespace n ON n.oid = src.relnamespace
         JOIN pg_catalog.pg_attribute sa
           ON sa.attrelid = src.oid AND sa.attname = 'tenant_id' AND NOT sa.attisdropped
         JOIN pg_catalog.pg_attribute da
           ON da.attrelid = dst.oid AND da.attname = 'tenant_id' AND NOT da.attisdropped
         WHERE con.contype = 'f' AND n.nspname = $1
           AND NOT EXISTS (
               SELECT 1 FROM unnest(con.conkey, con.confkey) AS k(src_col, dst_col)
               WHERE k.src_col = sa.attnum AND k.dst_col = da.attnum
           )
         ORDER BY 1",
    )
    .bind(SCHEMA)
    .fetch_all(&mut *conn)
    .await?;
    for (name, table) in &fks {
        problems.push(format!(
            "table {SCHEMA}.{table}: foreign key {name} does not include tenant_id, so a row could reference another tenant's row"
        ));
    }

    // Every role a runtime login could act as: the members of the runtime
    // group (its logins), and every role any of them can reach by
    // membership, with or without INHERIT. None of those may own anything
    // in the schema or be a superuser or BYPASSRLS. The walk follows
    // pg_auth_members rather than pg_has_role, which is always true for a
    // superuser and would count every superuser as a member.
    let (exists, owned, privileged): (bool, i64, bool) = sqlx::query_as(
        "WITH RECURSIVE
         g AS (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = $2),
         members(oid) AS (
             SELECT oid FROM g
             UNION
             SELECT am.member FROM pg_catalog.pg_auth_members am
             JOIN members m ON am.roleid = m.oid
         ),
         reach(oid) AS (
             SELECT oid FROM members
             UNION
             SELECT am.roleid FROM pg_catalog.pg_auth_members am
             JOIN reach r ON am.member = r.oid
         ),
         owners AS (
             SELECT n.nspowner AS owner FROM pg_catalog.pg_namespace n WHERE n.nspname = $1
             UNION ALL
             SELECT c.relowner FROM pg_catalog.pg_class c
             JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1
             UNION ALL
             SELECT f.proowner FROM pg_catalog.pg_proc f
             JOIN pg_catalog.pg_namespace n ON n.oid = f.pronamespace WHERE n.nspname = $1
             UNION ALL
             SELECT t.typowner FROM pg_catalog.pg_type t
             JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname = $1
         )
         SELECT EXISTS (SELECT 1 FROM g),
                (SELECT count(*) FROM owners WHERE owner IN (SELECT oid FROM reach)),
                EXISTS (SELECT 1 FROM pg_catalog.pg_roles o
                        WHERE (o.rolsuper OR o.rolbypassrls) AND o.oid IN (SELECT oid FROM reach))",
    )
    .bind(SCHEMA)
    .bind(RUNTIME_GROUP)
    .fetch_one(&mut *conn)
    .await?;
    if !exists {
        problems.push(format!(
            "role {RUNTIME_GROUP} does not exist; run sql/bootstrap.sql"
        ));
    }
    if owned > 0 {
        problems.push(format!(
            "{owned} object(s) in schema {SCHEMA} are owned by a role that a {RUNTIME_GROUP} login can act as"
        ));
    }
    if privileged {
        problems.push(format!(
            "a {RUNTIME_GROUP} login can act as a superuser or BYPASSRLS role"
        ));
    }
    Ok(problems)
}

/// Start-up database work for `serve`, run before any listener binds.
///
/// - With `auto_migrate`, connects as the migration role and applies pending
///   migrations ([`migrate_up`] refuses a wrong role, and a newer or damaged
///   schema).
/// - Builds the runtime pool and, if the database is reachable, refuses a
///   runtime login that could bypass row-level security, and a schema that
///   is newer than this binary or damaged.
///
/// An unreachable database does not stop the server: it starts not ready
/// (`database_down`) and [`watch`] keeps checking. Migrations that could
/// not run because the database was unreachable are not retried until the
/// next start or `migrate up`.
pub async fn start(settings: &DatabaseSettings) -> Result<Database, DbError> {
    check_pg_env()?;
    if settings.auto_migrate {
        let options = migration_options(settings)?;
        match connect(&options, settings.connect_timeout).await {
            Ok(mut conn) => {
                let result = migrate_up(&mut conn).await;
                let _ = conn.close().await;
                let state = result?;
                tracing::info!(
                    schema_version = state.applied_version(),
                    "database schema is current"
                );
            }
            Err(e) => tracing::warn!(
                error = %e,
                "cannot reach the database to migrate; starting not ready"
            ),
        }
    }
    let database = Database::connect_runtime(settings)?;
    let checked = tokio::time::timeout(settings.connect_timeout, async {
        let mut conn = database.pool().acquire().await?;
        let problems = role_facts(&mut conn).await?.problems();
        let state = schema_state(&mut conn).await?;
        Ok::<_, DbError>((problems, state))
    })
    .await;
    match checked {
        Ok(Ok((problems, _))) if !problems.is_empty() => {
            return Err(DbError(problems.join("; ")));
        }
        Ok(Ok((_, state))) => match state.verdict() {
            SchemaVerdict::Newer => {
                return Err(DbError(
                    "the database schema is newer than this binary; upgrade palisade-server"
                        .to_owned(),
                ));
            }
            SchemaVerdict::Damaged => {
                return Err(DbError(
                    "the database schema does not match this binary's migrations; run `migrate verify` for details".to_owned(),
                ));
            }
            SchemaVerdict::Behind | SchemaVerdict::Current => {}
        },
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "cannot check the database yet; starting not ready");
        }
        Err(_) => tracing::warn!("the database check timed out; starting not ready"),
    }
    Ok(database)
}

/// The database state for readiness, with the reason when it is not up.
/// The whole check is bounded by the connect timeout, so a stalled
/// connection or a lock on the history table reports the database as down
/// instead of freezing readiness at its last state.
pub async fn health_check(database: &Database) -> (DatabaseHealth, String) {
    match tokio::time::timeout(database.check_timeout, health_check_inner(database)).await {
        Ok(r) => r,
        Err(_) => (
            DatabaseHealth::Down,
            "the database check timed out".to_owned(),
        ),
    }
}

async fn health_check_inner(database: &Database) -> (DatabaseHealth, String) {
    let mut conn = match database.pool().acquire().await {
        Ok(c) => c,
        Err(e) => return (DatabaseHealth::Down, DbError::from(e).0),
    };
    let facts = match role_facts(&mut conn).await {
        Ok(f) => f,
        Err(e) => return (DatabaseHealth::Down, e.0),
    };
    let problems = facts.problems();
    if !problems.is_empty() {
        return (DatabaseHealth::RoleUnsafe, problems.join("; "));
    }
    match schema_state(&mut conn).await {
        Ok(s) if s.verdict() == SchemaVerdict::Current => (DatabaseHealth::Up, String::new()),
        Ok(s) => (
            DatabaseHealth::Schema(s.verdict()),
            format!("the schema is {}", s.verdict().as_str()),
        ),
        Err(e) => (DatabaseHealth::Down, e.0),
    }
}

/// Runs [`health_check`] every `interval` and records the result in
/// `health`, logging each change, until the task is aborted.
pub async fn watch(database: Database, health: Arc<Health>, interval: Duration) {
    let mut last: Option<DatabaseHealth> = None;
    loop {
        let (state, reason) = health_check(&database).await;
        if last != Some(state) {
            if state == DatabaseHealth::Up {
                tracing::info!("database ready");
            } else {
                tracing::warn!(reason = %reason, "database not ready");
            }
        }
        health.set_database(state);
        last = Some(state);
        tokio::time::sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn applied(m: &Migrator) -> Vec<(i64, String, Vec<u8>, bool)> {
        m.iter()
            .map(|x| {
                (
                    x.version,
                    x.description.to_string(),
                    x.checksum.to_vec(),
                    true,
                )
            })
            .collect()
    }

    #[test]
    fn embedded_migrations_are_numbered_from_one_without_gaps() {
        let versions: Vec<i64> = migrator().iter().map(|m| m.version).collect();
        let expected: Vec<i64> = (1..=i64::try_from(versions.len()).unwrap()).collect();
        assert_eq!(versions, expected);
        assert!(
            migrator()
                .iter()
                .all(|m| !m.migration_type.is_down_migration()),
            "forward-only"
        );
        assert!(
            migrator().iter().all(|m| !m.no_tx),
            "every migration runs in a transaction"
        );
        assert_eq!(migrator().table_name, HISTORY_TABLE);
        assert_eq!(&*migrator().create_schemas, [SCHEMA]);
    }

    #[test]
    fn verdicts() {
        assert_eq!(compare(migrator(), &[]).verdict(), SchemaVerdict::Behind);
        let all = applied(migrator());
        let s = compare(migrator(), &all);
        assert_eq!(s.verdict(), SchemaVerdict::Current);
        assert_eq!(s.applied_version(), s.embedded_version());

        let mut newer = all.clone();
        newer.push((9999, "future".to_owned(), vec![0; 48], true));
        assert_eq!(compare(migrator(), &newer).verdict(), SchemaVerdict::Newer);

        let mut changed = all.clone();
        changed[0].2[0] ^= 0xff;
        let s = compare(migrator(), &changed);
        assert_eq!(s.verdict(), SchemaVerdict::Damaged);
        assert!(s.migrations[0].checksum_mismatch);

        let mut failed = all;
        failed.last_mut().unwrap().3 = false;
        assert_eq!(
            compare(migrator(), &failed).verdict(),
            SchemaVerdict::Damaged
        );
        // Damaged wins over newer.
        changed.push((9999, "future".to_owned(), vec![0; 48], true));
        assert_eq!(
            compare(migrator(), &changed).verdict(),
            SchemaVerdict::Damaged
        );
    }

    #[test]
    fn scope_value_is_a_sorted_uuid_array_literal() {
        let a = Uuid::from_u128(2);
        let b = Uuid::from_u128(1);
        let s = TenantScope::new([a, b, a]).unwrap();
        assert_eq!(
            s.setting_value(),
            "{00000000-0000-0000-0000-000000000001,00000000-0000-0000-0000-000000000002}"
        );
        assert_eq!(TenantScope::new([]).unwrap().setting_value(), "{}");
        let too_many = (0..=MAX_SCOPE as u128).map(Uuid::from_u128);
        assert!(TenantScope::new(too_many).is_err());
    }

    #[test]
    fn role_problems() {
        let good = RoleFacts {
            role_name: "app".to_owned(),
            superuser: false,
            bypass_rls: false,
            in_runtime_group: true,
            owns_objects: false,
            can_create: false,
        };
        assert!(good.problems().is_empty());
        let bad = RoleFacts {
            superuser: true,
            bypass_rls: true,
            in_runtime_group: false,
            owns_objects: true,
            can_create: true,
            ..good
        };
        let p = bad.problems().join("\n");
        for needle in [
            "superuser",
            "BYPASSRLS",
            "owns objects",
            "can create",
            "not a member",
        ] {
            assert!(p.contains(needle), "{needle} missing in {p}");
        }
    }

    #[test]
    fn refused_env_lists_only_known_names() {
        let set = ["PGPASSWORD", "PGOPTIONS", "PGAPPNAME", "PALISADE_X"];
        assert_eq!(
            refused_env(|n| set.contains(&n)),
            ["PGPASSWORD", "PGOPTIONS"]
        );
        assert!(refused_env(|_| false).is_empty());
    }

    #[test]
    fn migration_errors_name_the_version_and_not_the_cause() {
        let e = DbError::from(MigrateError::VersionMismatch(2));
        assert!(
            e.0.contains("migration 2") && e.0.contains("checksum mismatch"),
            "{e}"
        );
        let e = DbError::from(MigrateError::VersionMissing(7));
        assert!(e.0.contains("newer than this binary"), "{e}");
    }
}
