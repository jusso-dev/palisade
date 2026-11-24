//! Tests against a real Postgres server (#127).
//!
//! They run only when `PALISADE_TEST_DATABASE_ADMIN_URL` names a superuser
//! connection to a disposable Postgres 16 or later, for example
//! `postgres://postgres:<pw>@127.0.0.1:5432/postgres`. CI sets it in the
//! `postgres` job. Without it every test here returns at once, so the other
//! jobs and platforms skip them cleanly.
//!
//! Each test bootstraps its own database and roles with `sql/bootstrap.sql`,
//! under names unique to the test, and drops them afterwards.

// Test helpers outside `#[test]` functions unwrap freely.
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use palisade_server::config::{self, DatabaseSettings};
use palisade_server::db::{self, Database, SchemaVerdict, TenantScope};
use palisade_server::health::{DatabaseHealth, Health};
use sqlx::postgres::PgConnectOptions;
use sqlx::types::Uuid;
use sqlx::{Connection as _, Executor as _, PgConnection};

const ADMIN_URL: &str = "PALISADE_TEST_DATABASE_ADMIN_URL";
const BIN: &str = env!("CARGO_BIN_EXE_palisade-server");
const BOOTSTRAP: &str = include_str!("../sql/bootstrap.sql");

fn admin_url() -> Option<String> {
    match std::env::var(ADMIN_URL) {
        Ok(u) if !u.is_empty() => Some(u),
        _ => {
            eprintln!("skipping: {ADMIN_URL} is not set");
            None
        }
    }
}

/// The refused `PG*` variables already set in this test process. The hosted
/// Windows x64 runner sets `PGPASSWORD` for its bundled PostgreSQL, so on that
/// runner the server's environment check (rightly) refuses before any
/// connection is tried. Tests that expect a connection
/// attempt check for this and assert the refusal instead. Tests cannot clear
/// the variables: changing the process environment is `unsafe` and races
/// with other tests.
fn inherited_refused_env() -> Vec<&'static str> {
    db::refused_env(|n| std::env::var_os(n).is_some())
}

#[track_caller]
fn assert_refused_for(e: &db::DbError, names: &[&str]) {
    for n in names {
        assert!(e.0.contains(n), "the refusal should name {n}: {}", e.0);
    }
}

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A database with its owner and runtime roles, made by the bootstrap
/// script, plus a palisade-server configuration for it. Dropped at the end
/// of the test.
struct Fixture {
    admin_url: String,
    database: String,
    owner: String,
    runtime: String,
    dir: PathBuf,
    settings: DatabaseSettings,
    config_path: PathBuf,
    /// Holds a session advisory lock, shared or exclusive, until the fixture
    /// is dropped (see [`ROLE_LOCK`]).
    _lock: PgConnection,
}

/// `palisade_runtime` is one role for the whole Postgres cluster, so a test
/// that gives a runtime login a dangerous membership (correctly) makes
/// `verify_structure` fail for every other database. Such tests hold this
/// advisory lock exclusively and every other fixture holds it shared, so
/// they never overlap. It works across test processes (nextest) and
/// threads (`cargo test`) alike.
const ROLE_LOCK: i64 = 0x7061_6c69_7361_6465; // "palisade"

#[derive(Clone, Copy, PartialEq, Eq)]
enum Roles {
    /// The test leaves roles and memberships alone.
    Untouched,
    /// The test changes role attributes or memberships.
    Changed,
}

/// A fresh random password, as hex.
fn password() -> String {
    let mut b = [0u8; 18];
    palisade_server::tls::fill_random(&mut b).unwrap();
    b.iter().map(|x| format!("{x:02x}")).collect()
}

async fn admin(url: &str) -> PgConnection {
    PgConnection::connect(url).await.unwrap()
}

/// Runs the bootstrap script with the psql variables substituted. The
/// names are generated here, from `[a-z0-9_]` only, so substituting them
/// as quoted identifiers is safe. The script has one `\connect` line; the
/// part after it runs in the new database.
async fn bootstrap(url: &str, owner: &str, runtime: &str, database: &str) {
    let script = BOOTSTRAP
        .replace(":\"owner\"", &format!("\"{owner}\""))
        .replace(":\"runtime_user\"", &format!("\"{runtime}\""))
        .replace(":\"database\"", &format!("\"{database}\""));
    let body: String = script
        .lines()
        .filter(|l| !l.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n");
    let (before, after) = body
        .split_once(&format!("\\connect \"{database}\""))
        .expect("bootstrap.sql has one \\connect line");
    let mut conn = admin(url).await;
    // CREATE DATABASE cannot run inside a multi-statement batch, so run
    // each statement on its own. The DO block contains semicolons inside
    // `$$`, so split on statement ends outside dollar quotes.
    for stmt in split_statements(before) {
        conn.execute(sqlx::AssertSqlSafe(stmt)).await.unwrap();
    }
    conn.close().await.unwrap();
    let mut conn = admin(&db_url(url, database)).await;
    for stmt in split_statements(after) {
        conn.execute(sqlx::AssertSqlSafe(stmt)).await.unwrap();
    }
    conn.close().await.unwrap();
}

fn split_statements(sql: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_dollar = false;
    let mut chars = sql.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '$' && chars.peek() == Some(&'$') {
            chars.next();
            in_dollar = !in_dollar;
            cur.push_str("$$");
            continue;
        }
        if c == ';' && !in_dollar {
            if !cur.trim().is_empty() {
                out.push(cur.trim().to_owned());
            }
            cur.clear();
            continue;
        }
        cur.push(c);
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_owned());
    }
    out
}

/// `url` with its database replaced.
fn db_url(url: &str, database: &str) -> String {
    let (base, _) = url.rsplit_once('/').unwrap();
    let base = base.to_owned();
    format!("{base}/{database}")
}

fn write_password(path: &Path, pw: &str) {
    common::write_secret(path, &format!("{pw}\n"));
}

impl Fixture {
    async fn new(tag: &str) -> Option<Self> {
        Self::with(tag, Roles::Untouched).await
    }

    async fn with(tag: &str, roles: Roles) -> Option<Self> {
        let admin_url = admin_url()?;
        let mut lock = admin(&admin_url).await;
        let take = match roles {
            Roles::Untouched => "SELECT pg_advisory_lock_shared($1)",
            Roles::Changed => "SELECT pg_advisory_lock($1)",
        };
        sqlx::query(take)
            .bind(ROLE_LOCK)
            .execute(&mut lock)
            .await
            .unwrap();
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let suffix = format!("{}_{}_{n}", tag, std::process::id());
        let database = format!("pal_{suffix}");
        let owner = format!("pal_owner_{suffix}");
        let runtime = format!("pal_app_{suffix}");
        bootstrap(&admin_url, &owner, &runtime, &database).await;

        let owner_pw = password();
        let runtime_pw = password();
        let mut conn = admin(&admin_url).await;
        for (role, pw) in [(&owner, &owner_pw), (&runtime, &runtime_pw)] {
            // ALTER ROLE does not take bind parameters; both values are
            // generated above from a fixed alphabet.
            conn.execute(sqlx::AssertSqlSafe(format!(
                "ALTER ROLE \"{role}\" PASSWORD '{pw}'"
            )))
            .await
            .unwrap();
        }
        conn.close().await.unwrap();

        let dir = common::temp_dir(&format!("pg-{tag}"));
        write_password(&dir.join("owner.password"), &owner_pw);
        write_password(&dir.join("runtime.password"), &runtime_pw);
        let opts: PgConnectOptions = admin_url.parse().unwrap();
        let toml = format!(
            "[database]\nhost = \"{}\"\nport = {}\nname = \"{database}\"\nuser = \"{runtime}\"\n\
             password_file = \"runtime.password\"\ntls = \"disable\"\nconnect_timeout_secs = 5\n\
             [database.migration]\nuser = \"{owner}\"\npassword_file = \"owner.password\"\n",
            opts.get_host(),
            opts.get_port(),
        );
        let config_path = dir.join("db.toml");
        std::fs::write(&config_path, format!("{SERVER_PART}{toml}")).unwrap();
        let settings = db_settings(&toml, &dir);
        Some(Self {
            admin_url,
            database,
            owner,
            runtime,
            dir,
            settings,
            config_path,
            _lock: lock,
        })
    }

    async fn migrate(&self) {
        let mut conn = db::connect_migration(&self.settings).await.unwrap();
        let state = db::migrate_up(&mut conn).await.unwrap();
        assert_eq!(state.verdict(), SchemaVerdict::Current);
        conn.close().await.unwrap();
    }

    async fn owner_conn(&self) -> PgConnection {
        db::connect_migration(&self.settings).await.unwrap()
    }

    async fn runtime_conn(&self) -> PgConnection {
        let options = db::connect_options(&self.settings, &self.settings.runtime).unwrap();
        db::connect(&options, Duration::from_secs(5)).await.unwrap()
    }

    async fn superuser_db_conn(&self) -> PgConnection {
        admin(&db_url(&self.admin_url, &self.database)).await
    }
}

/// The non-database part of a valid configuration. `migrate` loads and
/// validates the whole file, as `serve` does, but never reads the TLS files.
const SERVER_PART: &str = "[tls]\ncert_file = \"c\"\nkey_file = \"k\"\n\
    [listen.admin]\nbind = \"127.0.0.1\"\nport = 1\n\
    [listen.agent]\nbind = \"127.0.0.1\"\nport = 2\nclient_ca_file = \"a\"\n";

impl Drop for Fixture {
    /// Drops the database and roles even when the test panicked. Runs on its
    /// own thread and runtime, because `Drop` cannot be async and the test's
    /// runtime may be shutting down.
    fn drop(&mut self) {
        let admin_url = self.admin_url.clone();
        let database = self.database.clone();
        // Extra roles a test made from the owner's name, then the two
        // fixture roles.
        let prefix = self.owner.clone();
        let roles = [self.owner.clone(), self.runtime.clone()];
        let cleanup = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let mut conn = admin(&admin_url).await;
                conn.execute(sqlx::AssertSqlSafe(format!(
                    "DROP DATABASE IF EXISTS \"{database}\" WITH (FORCE)"
                )))
                .await
                .unwrap();
                let extra: Vec<String> = sqlx::query_scalar(
                    "SELECT rolname::text FROM pg_roles WHERE starts_with(rolname, $1 || '_')
                     ORDER BY length(rolname) DESC",
                )
                .bind(&prefix)
                .fetch_all(&mut conn)
                .await
                .unwrap();
                for role in extra.into_iter().chain(roles) {
                    conn.execute(sqlx::AssertSqlSafe(format!(
                        "DROP ROLE IF EXISTS \"{role}\""
                    )))
                    .await
                    .unwrap();
                }
                conn.close().await.unwrap();
            });
        });
        let _ = cleanup.join();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Parses a `[database]` TOML fragment into settings, with relative paths
/// resolved against `dir`.
fn db_settings(toml: &str, dir: &Path) -> DatabaseSettings {
    let full = format!("{SERVER_PART}{toml}");
    config::load_str(&full, "db.toml", dir, &[])
        .unwrap()
        .config
        .database
        .unwrap()
}

/// Inserts a root tenant and one organisation tenant with a group, as the
/// migration role, which owns the tables. FORCE ROW LEVEL SECURITY applies
/// to it too, so it sets its own scope.
async fn seed(f: &Fixture, root: Uuid, org: Uuid, group: Uuid, name: &str) {
    let mut conn = f.owner_conn().await;
    let mut tx = conn.begin().await.unwrap();
    sqlx::query("SELECT set_config('palisade.tenant_ids', $1, true)")
        .bind(format!("{{{root},{org}}}"))
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO palisade.tenant (id, parent_id, kind, slug, display_name)
         VALUES ($1, NULL, 'root', 'root', 'Root')
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(root)
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO palisade.tenant (id, parent_id, kind, slug, display_name)
         VALUES ($1, $2, 'organisation', $3, $3)",
    )
    .bind(org)
    .bind(root)
    .bind(name)
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query("INSERT INTO palisade.computer_group (id, tenant_id, name) VALUES ($1, $2, $3)")
        .bind(group)
        .bind(org)
        .bind(format!("{name} workstations"))
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    conn.close().await.unwrap();
}

fn id(n: u128) -> Uuid {
    // Version-7-shaped constants, distinct per test value.
    Uuid::from_u128(0x0190_0000_0000_7000_8000_0000_0000_0000 | n)
}

#[tokio::test]
async fn migrations_apply_and_verify_on_a_clean_database() {
    let Some(f) = Fixture::new("clean").await else {
        return;
    };
    let mut conn = f.owner_conn().await;
    assert_eq!(
        db::schema_state(&mut conn).await.unwrap().verdict(),
        SchemaVerdict::Behind
    );
    let started = std::time::Instant::now();
    let state = db::migrate_up(&mut conn).await.unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "AC: under 30 s"
    );
    assert_eq!(state.verdict(), SchemaVerdict::Current);
    assert!(db::verify_structure(&mut conn).await.unwrap().is_empty());
    // Running again is a no-op.
    let again = db::migrate_up(&mut conn).await.unwrap();
    assert_eq!(again, state);
    conn.close().await.unwrap();
}

#[tokio::test]
async fn a_tenant_cannot_see_or_touch_another_tenants_rows_through_the_runtime_role() {
    let Some(f) = Fixture::new("leak").await else {
        return;
    };
    f.migrate().await;
    let (root, a, b) = (id(1), id(0xa), id(0xb));
    let (group_a, group_b) = (id(0xa1), id(0xb1));
    seed(&f, root, a, group_a, "tenant-a").await;
    seed(&f, root, b, group_b, "tenant-b").await;

    let database = Database::connect_runtime(&f.settings).unwrap();

    // Tenant A sees its own tenant row and group, and nothing of B, even
    // with queries that ask for B's rows by ID and no filter at all.
    let mut tx = database.tenant_tx(&TenantScope::one(a)).await.unwrap();
    let groups: Vec<(Uuid, Uuid)> =
        sqlx::query_as("SELECT id, tenant_id FROM palisade.computer_group")
            .fetch_all(tx.conn())
            .await
            .unwrap();
    assert_eq!(groups, [(group_a, a)]);
    let tenants: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM palisade.tenant")
        .fetch_all(tx.conn())
        .await
        .unwrap();
    assert_eq!(tenants, [a], "not the root, not B");
    let by_id: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM palisade.computer_group WHERE id = $1")
            .bind(group_b)
            .fetch_optional(tx.conn())
            .await
            .unwrap();
    assert_eq!(by_id, None);

    // Writes into B are invisible or refused.
    let updated = sqlx::query("UPDATE palisade.computer_group SET name = 'pwned' WHERE id = $1")
        .bind(group_b)
        .execute(tx.conn())
        .await
        .unwrap();
    assert_eq!(updated.rows_affected(), 0);
    let deleted = sqlx::query("DELETE FROM palisade.computer_group WHERE tenant_id = $1")
        .bind(b)
        .execute(tx.conn())
        .await
        .unwrap();
    assert_eq!(deleted.rows_affected(), 0);
    tx.rollback().await.unwrap();

    let mut tx = database.tenant_tx(&TenantScope::one(a)).await.unwrap();
    let insert = sqlx::query(
        "INSERT INTO palisade.computer_group (id, tenant_id, name) VALUES ($1, $2, 'x')",
    )
    .bind(id(0xa2))
    .bind(b)
    .execute(tx.conn())
    .await
    .unwrap_err();
    assert_sqlstate(&insert, "42501"); // WITH CHECK violation
    tx.rollback().await.unwrap();

    // A row cannot move to another tenant, even within a scope that holds
    // both.
    let both = TenantScope::new([a, b]).unwrap();
    let mut tx = database.tenant_tx(&both).await.unwrap();
    let moved = sqlx::query("UPDATE palisade.computer_group SET tenant_id = $1 WHERE id = $2")
        .bind(b)
        .bind(group_a)
        .execute(tx.conn())
        .await
        .unwrap_err();
    assert_sqlstate(&moved, "23514");
    tx.rollback().await.unwrap();

    // A group in A cannot name a parent in B: the foreign key includes
    // tenant_id.
    let mut tx = database.tenant_tx(&both).await.unwrap();
    let cross = sqlx::query(
        "INSERT INTO palisade.computer_group (id, tenant_id, parent_id, name) VALUES ($1, $2, $3, 'child')",
    )
    .bind(id(0xa3))
    .bind(a)
    .bind(group_b)
    .execute(tx.conn())
    .await
    .unwrap_err();
    assert_sqlstate(&cross, "23503");
    tx.rollback().await.unwrap();

    // B sees only B, through the same pool.
    let mut tx = database.tenant_tx(&TenantScope::one(b)).await.unwrap();
    let groups: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM palisade.computer_group")
        .fetch_all(tx.conn())
        .await
        .unwrap();
    assert_eq!(groups, [group_b]);
    tx.commit().await.unwrap();

    database.close().await;
}

#[tokio::test]
async fn no_scope_means_no_rows_and_the_scope_ends_with_the_transaction() {
    let Some(f) = Fixture::new("scope").await else {
        return;
    };
    f.migrate().await;
    let (root, a) = (id(1), id(0xa));
    seed(&f, root, a, id(0xa1), "tenant-a").await;

    // A pool of one connection, so every transaction reuses it.
    let mut settings = f.settings.clone();
    settings.max_connections = 1;
    let database = Database::connect_runtime(&settings).unwrap();

    let mut tx = database.tenant_tx(&TenantScope::one(a)).await.unwrap();
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM palisade.computer_group")
        .fetch_one(tx.conn())
        .await
        .unwrap();
    assert_eq!(n, 1);
    tx.commit().await.unwrap();

    // Outside a tenant transaction, on the same pooled connection, the
    // setting is gone and RLS fails closed.
    let mut conn = database.pool().acquire().await.unwrap();
    let setting: Option<String> =
        sqlx::query_scalar("SELECT NULLIF(current_setting('palisade.tenant_ids', true), '')")
            .fetch_one(&mut *conn)
            .await
            .unwrap();
    assert_eq!(setting, None, "the scope did not outlive its transaction");
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM palisade.computer_group")
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    assert_eq!(n, 0, "no scope, no rows");
    drop(conn);

    // An empty scope sees nothing.
    let mut tx = database
        .tenant_tx(&TenantScope::new([]).unwrap())
        .await
        .unwrap();
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM palisade.tenant")
        .fetch_one(tx.conn())
        .await
        .unwrap();
    assert_eq!(n, 0);
    tx.rollback().await.unwrap();

    // A rolled-back scope ends too.
    let tx = database.tenant_tx(&TenantScope::one(a)).await.unwrap();
    drop(tx);
    let mut conn = database.pool().acquire().await.unwrap();
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM palisade.computer_group")
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    assert_eq!(
        n, 0,
        "dropping the transaction rolled it back with its scope"
    );
    drop(conn);

    database.close().await;
}

#[tokio::test]
async fn the_runtime_role_cannot_disable_or_bypass_row_level_security() {
    let Some(f) = Fixture::new("bypass").await else {
        return;
    };
    f.migrate().await;
    let (root, a, b) = (id(1), id(0xa), id(0xb));
    seed(&f, root, a, id(0xa1), "tenant-a").await;
    seed(&f, root, b, id(0xb1), "tenant-b").await;

    let mut conn = f.runtime_conn().await;
    db::check_runtime_role(&mut conn).await.unwrap();

    for (sql, code) in [
        (
            "ALTER TABLE palisade.computer_group DISABLE ROW LEVEL SECURITY",
            "42501",
        ),
        (
            "ALTER TABLE palisade.computer_group NO FORCE ROW LEVEL SECURITY",
            "42501",
        ),
        (
            "DROP POLICY tenant_scope ON palisade.computer_group",
            "42501",
        ),
        (
            "CREATE POLICY open ON palisade.computer_group USING (true)",
            "42501",
        ),
        ("ALTER ROLE CURRENT_USER BYPASSRLS", "42501"),
        ("SET ROLE palisade_runtime", ""),
        ("CREATE TABLE palisade.mine (x int)", "42501"),
        ("CREATE TABLE public.mine (x int)", "42501"),
        (
            "CREATE OR REPLACE FUNCTION palisade.current_tenant_ids() RETURNS uuid[] LANGUAGE sql AS 'SELECT NULL::uuid[]'",
            "42501",
        ),
        ("TRUNCATE palisade.computer_group", "42501"),
        ("DELETE FROM palisade._sqlx_migrations", "42501"),
    ] {
        match conn.execute(sql).await {
            Ok(_) if code.is_empty() => {}
            Ok(_) => panic!("`{sql}` succeeded as the runtime role"),
            Err(e) => assert_sqlstate(&e, code),
        }
    }
    conn.execute("RESET ROLE").await.unwrap();

    // Turning row_security off makes a query that RLS would filter fail,
    // rather than return every row.
    conn.execute("SET row_security = off").await.unwrap();
    let mut tx = conn.begin().await.unwrap();
    sqlx::query("SELECT set_config('palisade.tenant_ids', $1, true)")
        .bind(format!("{{{a}}}"))
        .execute(&mut *tx)
        .await
        .unwrap();
    let e = sqlx::query("SELECT id FROM palisade.computer_group")
        .fetch_all(&mut *tx)
        .await
        .unwrap_err();
    assert_sqlstate(&e, "42501");
    tx.rollback().await.unwrap();
    conn.execute("RESET row_security").await.unwrap();

    // A forged, broken scope fails instead of matching anything.
    let mut tx = conn.begin().await.unwrap();
    sqlx::query("SELECT set_config('palisade.tenant_ids', 'not-a-uuid-array', true)")
        .execute(&mut *tx)
        .await
        .unwrap();
    let e = sqlx::query("SELECT id FROM palisade.computer_group")
        .fetch_all(&mut *tx)
        .await
        .unwrap_err();
    assert_sqlstate(&e, "22P02");
    tx.rollback().await.unwrap();

    // What AC-08 says RLS does not stop: a process holding the runtime role
    // chooses its own scope. Asking for B returns B's rows.
    let mut tx = conn.begin().await.unwrap();
    sqlx::query("SELECT set_config('palisade.tenant_ids', $1, true)")
        .bind(format!("{{{b}}}"))
        .execute(&mut *tx)
        .await
        .unwrap();
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM palisade.computer_group")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(
        n, 1,
        "documented limit: RLS is not a defence against the runtime role itself"
    );
    tx.rollback().await.unwrap();

    conn.close().await.unwrap();
}

#[tokio::test]
async fn an_unsafe_runtime_role_is_reported() {
    let Some(f) = Fixture::with("unsafe", Roles::Changed).await else {
        return;
    };
    f.migrate().await;
    // Serving requests as the owner is refused.
    let mut owner = f.owner_conn().await;
    let problems = db::role_facts(&mut owner)
        .await
        .unwrap()
        .problems()
        .join("\n");
    assert!(problems.contains("owns objects"), "{problems}");
    owner.close().await.unwrap();

    let database = Database::connect_runtime(&f.settings).unwrap();
    assert_eq!(db::health_check(&database).await.0, DatabaseHealth::Up);
    let mut su = admin(&f.admin_url).await;
    su.execute(sqlx::AssertSqlSafe(format!(
        "ALTER ROLE \"{}\" BYPASSRLS",
        f.runtime
    )))
    .await
    .unwrap();
    su.close().await.unwrap();
    // A new connection sees the change.
    database.close().await;
    let database = Database::connect_runtime(&f.settings).unwrap();
    let (state, reason) = db::health_check(&database).await;
    assert_eq!(state, DatabaseHealth::RoleUnsafe);
    assert!(reason.contains("BYPASSRLS"), "{reason}");
    database.close().await;
}

#[tokio::test]
async fn readiness_reports_the_database() {
    let Some(f) = Fixture::new("ready").await else {
        return;
    };
    let health = std::sync::Arc::new(Health::new([]));
    let database = Database::connect_runtime(&f.settings).unwrap();

    // Reachable but not migrated.
    let (state, _) = db::health_check(&database).await;
    assert_eq!(state, DatabaseHealth::Schema(SchemaVerdict::Behind));

    f.migrate().await;
    let watcher = tokio::spawn(db::watch(
        database.clone(),
        health.clone(),
        Duration::from_millis(50),
    ));
    wait_for(&health, DatabaseHealth::Up).await;
    assert!(health.readiness().ready);

    // A schema newer than the binary is not ready.
    let mut su = f.superuser_db_conn().await;
    su.execute(
        "INSERT INTO palisade._sqlx_migrations (version, description, success, checksum, execution_time)
         VALUES (9999, 'from the future', true, '\\x00', 0)",
    )
    .await
    .unwrap();
    wait_for(&health, DatabaseHealth::Schema(SchemaVerdict::Newer)).await;
    let body = health.readiness().body;
    assert_eq!(
        body["indicators"],
        serde_json::json!(["database_schema:newer"])
    );
    su.execute("DELETE FROM palisade._sqlx_migrations WHERE version = 9999")
        .await
        .unwrap();
    wait_for(&health, DatabaseHealth::Up).await;
    su.close().await.unwrap();

    watcher.abort();
    database.close().await;
}

#[tokio::test]
async fn readiness_reports_an_unreachable_database_as_down() {
    // Needs no Postgres: nothing listens on the port.
    let dir = common::temp_dir("pg-down");
    write_password(&dir.join("runtime.password"), "unused");
    let port = common::free_port();
    let settings = db_settings(
        &format!(
            "[database]\nhost = \"127.0.0.1\"\nport = {port}\nname = \"p\"\nuser = \"app\"\n\
             password_file = \"runtime.password\"\ntls = \"disable\"\nconnect_timeout_secs = 1\n"
        ),
        &dir,
    );
    let inherited = inherited_refused_env();
    if !inherited.is_empty() {
        let e = Database::connect_runtime(&settings).unwrap_err();
        assert_refused_for(&e, &inherited);
        return;
    }
    let database = Database::connect_runtime(&settings).unwrap();
    let health = std::sync::Arc::new(Health::new([]));
    let watcher = tokio::spawn(db::watch(
        database,
        health.clone(),
        Duration::from_millis(50),
    ));
    wait_for(&health, DatabaseHealth::Down).await;
    let r = health.readiness();
    assert!(!r.ready);
    assert_eq!(r.body["indicators"], serde_json::json!(["database_down"]));
    watcher.abort();
}

#[tokio::test]
async fn a_changed_migration_is_a_checksum_mismatch() {
    let Some(f) = Fixture::new("checksum").await else {
        return;
    };
    f.migrate().await;
    let mut su = f.superuser_db_conn().await;
    su.execute("UPDATE palisade._sqlx_migrations SET checksum = '\\x00' WHERE version = 1")
        .await
        .unwrap();
    su.close().await.unwrap();
    let mut conn = f.owner_conn().await;
    let state = db::schema_state(&mut conn).await.unwrap();
    assert_eq!(state.verdict(), SchemaVerdict::Damaged);
    let e = db::migrate_up(&mut conn).await.unwrap_err();
    assert!(e.0.contains("migrate verify"), "{e}");
    conn.close().await.unwrap();

    let (code, _, err) = run(&["migrate", "verify", "-c", f.config_path.to_str().unwrap()]);
    assert_eq!(code, 1, "{err}");
    assert!(
        err.contains("migration 1") && err.contains("checksum mismatch"),
        "{err}"
    );
}

#[tokio::test]
async fn verify_finds_a_table_without_forced_rls() {
    let Some(f) = Fixture::new("noforce").await else {
        return;
    };
    f.migrate().await;
    let mut owner = f.owner_conn().await;
    owner
        .execute("ALTER TABLE palisade.computer_group NO FORCE ROW LEVEL SECURITY")
        .await
        .unwrap();
    owner
        .execute(
            "CREATE TABLE palisade.loose (id uuid PRIMARY KEY, tenant_id uuid NOT NULL,
                 group_id uuid REFERENCES palisade.computer_group (id))",
        )
        .await
        .unwrap();
    let problems = db::verify_structure(&mut owner).await.unwrap().join("\n");
    owner.close().await.unwrap();
    for needle in [
        "palisade.computer_group: row-level security is not forced",
        "palisade.loose: row-level security is not enabled",
        "palisade.loose: has no row-level security policy",
        "does not include tenant_id",
    ] {
        assert!(
            problems.contains(needle),
            "missing {needle} in:\n{problems}"
        );
    }
}

#[tokio::test]
async fn migrate_commands_end_to_end() {
    let Some(f) = Fixture::new("cli").await else {
        return;
    };
    let cfg = f.config_path.to_str().unwrap();
    let (code, out, err) = run(&["migrate", "status", "-c", cfg]);
    assert_eq!(code, 3, "pending: {err}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["verdict"], "behind");

    let (code, out, err) = run(&["migrate", "up", "-c", cfg]);
    assert_eq!(code, 0, "{err}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["verdict"], "current");
    assert_eq!(v["applied_version"], v["embedded_version"]);

    let (code, _, err) = run(&["migrate", "verify", "-c", cfg]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("verify OK"), "{err}");
    let (code, _, _) = run(&["migrate", "status", "-c", cfg]);
    assert_eq!(code, 0);

    // Status and verify also work with the runtime login alone; up does not.
    let runtime_only = f.dir.join("runtime-only.toml");
    let text = std::fs::read_to_string(&f.config_path).unwrap();
    let (head, _) = text.split_once("[database.migration]").unwrap();
    std::fs::write(&runtime_only, head).unwrap();
    let ro = runtime_only.to_str().unwrap();
    let (code, _, err) = run(&["migrate", "verify", "-c", ro]);
    assert_eq!(code, 0, "{err}");
    let (code, _, err) = run(&["migrate", "up", "-c", ro]);
    assert_eq!(code, 1);
    assert!(
        err.contains("database.migration is not configured"),
        "{err}"
    );

    // Passwords never reach the output.
    let pw = std::fs::read_to_string(f.dir.join("owner.password")).unwrap();
    let (_, out, err) = run(&["migrate", "status", "-c", cfg]);
    assert!(!out.contains(pw.trim()) && !err.contains(pw.trim()));
}

#[test]
fn migrate_refuses_password_environment_variables() {
    // Needs no Postgres: the check runs before any connection.
    let dir = common::temp_dir("pg-env");
    write_password(&dir.join("runtime.password"), "unused");
    let cfg = dir.join("db.toml");
    std::fs::write(
        &cfg,
        format!(
            "{SERVER_PART}[database]\nhost = \"127.0.0.1\"\nname = \"p\"\nuser = \"app\"\n\
             password_file = \"runtime.password\"\ntls = \"disable\"\n"
        ),
    )
    .unwrap();
    let out = Command::new(BIN)
        .args(["migrate", "status", "-c", cfg.to_str().unwrap()])
        .env("PGPASSWORD", "sentinel-db-password")
        .env("PGOPTIONS", "-c row_security=off")
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "a configuration error: {err}");
    assert!(
        err.contains("PGPASSWORD") && err.contains("PGOPTIONS"),
        "{err}"
    );
    assert!(!err.contains("sentinel-db-password"), "{err}");
}

fn run(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(BIN).args(args).output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

async fn wait_for(health: &Health, want: DatabaseHealth) {
    for _ in 0..200 {
        if health.database() == Some(want) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!(
        "database health never became {want:?}: {:?}",
        health.database()
    );
}

#[track_caller]
fn assert_sqlstate(e: &sqlx::Error, code: &str) {
    let got = e
        .as_database_error()
        .and_then(|d| d.code())
        .map(|c| c.into_owned());
    assert_eq!(got.as_deref(), Some(code), "unexpected error: {e}");
}

#[tokio::test]
async fn the_server_is_not_ready_until_the_database_is() {
    let Some(f) = Fixture::new("serve").await else {
        return;
    };
    let pki = common::pki("pg-serve", &["localhost"]);
    let admin = common::free_port();
    let agent = common::free_port();
    let path = common::write_config(
        &pki,
        &format!(
            "[listen.admin]\nbind = \"127.0.0.1\"\nport = {admin}\n\
             [listen.agent]\nbind = \"127.0.0.1\"\nport = {agent}\nclient_ca_file = \"agent-ca.crt\"\n"
        ),
    );
    let cfg = config::load(&path, &[]).unwrap().config;
    let prepared = palisade_server::server::prepare(&cfg, &[]).unwrap();
    let running = palisade_server::server::Server::new(cfg, prepared)
        .with_database()
        .start();
    let health = running.health().clone();

    // Before any database check: listeners bind, but readiness fails.
    for _ in 0..200 {
        let body = health.readiness().body;
        if body["indicators"] == serde_json::json!(["database_down"]) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let r = readyz(&pki, admin).await;
    assert_eq!(r.status, 503, "{}", r.body);

    let database = Database::connect_runtime(&f.settings).unwrap();
    let watcher = tokio::spawn(db::watch(
        database.clone(),
        health.clone(),
        Duration::from_millis(50),
    ));
    wait_for(&health, DatabaseHealth::Schema(SchemaVerdict::Behind)).await;
    assert_eq!(readyz(&pki, admin).await.status, 503);

    f.migrate().await;
    wait_for(&health, DatabaseHealth::Up).await;
    let r = readyz(&pki, admin).await;
    assert_eq!(r.status, 200, "{}", r.body);

    watcher.abort();
    database.close().await;
    running.shutdown().await;
}

async fn readyz(pki: &common::Pki, port: u16) -> common::HttpResponse {
    let cfg = common::client_config(pki, &[&rustls::version::TLS13], None, &[b"http/1.1"]);
    let mut s = common::connect(
        cfg,
        std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        "localhost",
    )
    .await
    .unwrap();
    common::http1(&mut s, &common::get_request("/readyz")).await
}

#[tokio::test]
async fn the_trigger_owns_timestamps_and_revision() {
    let Some(f) = Fixture::new("touch").await else {
        return;
    };
    f.migrate().await;
    let (root, a) = (id(1), id(0xa));
    seed(&f, root, a, id(0xa1), "tenant-a").await;
    let database = Database::connect_runtime(&f.settings).unwrap();
    let g = id(0xa9);

    // Client-supplied bookkeeping on INSERT is ignored.
    let mut tx = database.tenant_tx(&TenantScope::one(a)).await.unwrap();
    sqlx::query(
        "INSERT INTO palisade.computer_group (id, tenant_id, name, created_at, updated_at, revision)
         VALUES ($1, $2, 'g', '2000-01-01', '2000-01-01', 42)",
    )
    .bind(g)
    .bind(a)
    .execute(tx.conn())
    .await
    .unwrap();
    let (rev, fresh, same): (i64, bool, bool) = sqlx::query_as(
        "SELECT revision, created_at > now() - interval '1 hour', created_at = updated_at
         FROM palisade.computer_group WHERE id = $1",
    )
    .bind(g)
    .fetch_one(tx.conn())
    .await
    .unwrap();
    assert_eq!((rev, fresh, same), (1, true, true));
    tx.commit().await.unwrap();

    // Each UPDATE adds 1 to the revision, keeps created_at and moves
    // updated_at, whatever the client sends. Separate transactions, because
    // now() is the transaction start time.
    for expected in 2..=3_i64 {
        let mut tx = database.tenant_tx(&TenantScope::one(a)).await.unwrap();
        let before: (String, String) = sqlx::query_as(
            "SELECT created_at::text, updated_at::text FROM palisade.computer_group WHERE id = $1",
        )
        .bind(g)
        .fetch_one(tx.conn())
        .await
        .unwrap();
        tx.commit().await.unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        let mut tx = database.tenant_tx(&TenantScope::one(a)).await.unwrap();
        let n = sqlx::query(
            "UPDATE palisade.computer_group
             SET name = $2, revision = 999, created_at = '2000-01-01', updated_at = '2000-01-01'
             WHERE id = $1",
        )
        .bind(g)
        .bind(format!("g{expected}"))
        .execute(tx.conn())
        .await
        .unwrap();
        assert_eq!(n.rows_affected(), 1);
        let after: (i64, String, String) = sqlx::query_as(
            "SELECT revision, created_at::text, updated_at::text FROM palisade.computer_group WHERE id = $1",
        )
        .bind(g)
        .fetch_one(tx.conn())
        .await
        .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(after.0, expected);
        assert_eq!(after.1, before.0, "created_at is kept");
        assert_ne!(after.2, before.1, "updated_at moves");
    }

    // The id cannot change.
    let mut tx = database.tenant_tx(&TenantScope::one(a)).await.unwrap();
    let e = sqlx::query("UPDATE palisade.computer_group SET id = $2 WHERE id = $1")
        .bind(g)
        .bind(id(0xaa))
        .execute(tx.conn())
        .await
        .unwrap_err();
    assert_sqlstate(&e, "23514");
    tx.rollback().await.unwrap();

    // The tenant table gets the same bookkeeping.
    let mut tx = database.tenant_tx(&TenantScope::one(a)).await.unwrap();
    sqlx::query("UPDATE palisade.tenant SET display_name = 'A2' WHERE id = $1")
        .bind(a)
        .execute(tx.conn())
        .await
        .unwrap();
    let rev: i64 = sqlx::query_scalar("SELECT revision FROM palisade.tenant WHERE id = $1")
        .bind(a)
        .fetch_one(tx.conn())
        .await
        .unwrap();
    assert_eq!(rev, 2);
    let e = sqlx::query("UPDATE palisade.tenant SET id = $2 WHERE id = $1")
        .bind(a)
        .bind(id(0xab))
        .execute(tx.conn())
        .await
        .unwrap_err();
    assert_sqlstate(&e, "23514");
    tx.rollback().await.unwrap();
    database.close().await;
}

/// Runs one statement as the runtime role in `scope`, rolled back, and
/// returns its SQLSTATE (empty on success).
async fn sqlstate_of(
    database: &Database,
    scope: &[Uuid],
    sql: &'static str,
    binds: &[Uuid],
) -> String {
    let mut tx = database
        .tenant_tx(&TenantScope::new(scope.iter().copied()).unwrap())
        .await
        .unwrap();
    let mut q = sqlx::query(sql);
    for b in binds {
        q = q.bind(*b);
    }
    let code = match q.execute(tx.conn()).await {
        Ok(_) => String::new(),
        Err(e) => e
            .as_database_error()
            .and_then(|d| d.code())
            .map(|c| c.into_owned())
            .unwrap_or_else(|| format!("{e}")),
    };
    tx.rollback().await.unwrap();
    code
}

#[tokio::test]
async fn table_constraints_hold() {
    let Some(f) = Fixture::new("constraints").await else {
        return;
    };
    f.migrate().await;
    let (root, a, g) = (id(1), id(0xa), id(0xa1));
    seed(&f, root, a, g, "tenant-a").await;
    let database = Database::connect_runtime(&f.settings).unwrap();
    let both = [root, a, id(0xc)];
    for (what, sql, binds, code) in [
        (
            "a second root",
            "INSERT INTO palisade.tenant (id, kind, slug, display_name) VALUES ($1, 'root', 'root2', 'R')",
            vec![id(0xc)],
            "23505",
        ),
        (
            "a non-root without a parent",
            "INSERT INTO palisade.tenant (id, kind, slug, display_name) VALUES ($1, 'organisation', 'orphan', 'O')",
            vec![id(0xc)],
            "23514",
        ),
        (
            "a root with a parent",
            "INSERT INTO palisade.tenant (id, parent_id, kind, slug, display_name) VALUES ($1, $2, 'root', 'r3', 'R')",
            vec![id(0xc), a],
            "23514",
        ),
        (
            "its own parent",
            "UPDATE palisade.tenant SET parent_id = id WHERE id = $1",
            vec![a],
            "23514",
        ),
        (
            "an upper-case slug",
            "INSERT INTO palisade.tenant (id, parent_id, kind, slug, display_name) VALUES ($1, $2, 'organisation', 'Bad', 'B')",
            vec![id(0xc), root],
            "23514",
        ),
        (
            "a duplicate slug",
            "INSERT INTO palisade.tenant (id, parent_id, kind, slug, display_name) VALUES ($1, $2, 'organisation', 'tenant-a', 'B')",
            vec![id(0xc), root],
            "23505",
        ),
        (
            "settings that are not an object",
            "UPDATE palisade.tenant SET settings = '[]' WHERE id = $1",
            vec![a],
            "23514",
        ),
        (
            "an empty display name",
            "UPDATE palisade.tenant SET display_name = '' WHERE id = $1",
            vec![a],
            "23514",
        ),
        (
            "deleting a tenant as the runtime role",
            "DELETE FROM palisade.tenant WHERE id = $1",
            vec![a],
            "42501",
        ),
        (
            "a duplicate top-level group name",
            "INSERT INTO palisade.computer_group (id, tenant_id, name) VALUES ($1, $2, 'tenant-a workstations')",
            vec![id(0xa2), a],
            "23505",
        ),
        (
            "a group that is its own parent",
            "UPDATE palisade.computer_group SET parent_id = id WHERE id = $1",
            vec![g],
            "23514",
        ),
    ] {
        assert_eq!(
            sqlstate_of(&database, &both, sql, &binds).await,
            code,
            "{what}"
        );
    }

    // Sibling names are unique under a parent too, and the same name is
    // fine under different parents.
    let mut tx = database.tenant_tx(&TenantScope::one(a)).await.unwrap();
    for (child, parent) in [(id(0xa3), g), (id(0xa4), id(0xa3))] {
        sqlx::query(
            "INSERT INTO palisade.computer_group (id, tenant_id, parent_id, name) VALUES ($1, $2, $3, 'child')",
        )
        .bind(child)
        .bind(a)
        .bind(parent)
        .execute(tx.conn())
        .await
        .unwrap();
    }
    let e = sqlx::query(
        "INSERT INTO palisade.computer_group (id, tenant_id, parent_id, name) VALUES ($1, $2, $3, 'child')",
    )
    .bind(id(0xa5))
    .bind(a)
    .bind(g)
    .execute(tx.conn())
    .await
    .unwrap_err();
    assert_sqlstate(&e, "23505");
    tx.rollback().await.unwrap();
    database.close().await;
}

#[tokio::test]
async fn migrations_refuse_the_wrong_role_without_changing_anything() {
    let Some(f) = Fixture::with("wrongrole", Roles::Changed).await else {
        return;
    };
    // A superuser on a clean database: refused, and nothing is created.
    let mut su = f.superuser_db_conn().await;
    let e = db::migrate_up(&mut su).await.unwrap_err();
    assert!(e.0.contains("superuser"), "{e}");
    let schema: Option<String> =
        sqlx::query_scalar("SELECT nspname::text FROM pg_namespace WHERE nspname = 'palisade'")
            .fetch_optional(&mut su)
            .await
            .unwrap();
    assert_eq!(schema, None, "the refused run created nothing");
    su.close().await.unwrap();

    // The owner role still migrates afterwards.
    f.migrate().await;

    // The runtime role cannot migrate: it does not own the schema.
    let mut rt = f.runtime_conn().await;
    let e = db::migrate_up(&mut rt).await.unwrap_err();
    assert!(e.0.contains("must not be members of each other"), "{e}");
    rt.close().await.unwrap();

    // Another non-owner role, unrelated to the runtime group, is refused
    // too: the schema already belongs to the owner.
    let other = format!("{}_other", f.owner);
    let pw = password();
    let mut su = admin(&f.admin_url).await;
    su.execute(sqlx::AssertSqlSafe(format!(
        "CREATE ROLE \"{other}\" LOGIN PASSWORD '{pw}'"
    )))
    .await
    .unwrap();
    su.execute(sqlx::AssertSqlSafe(format!(
        "GRANT CONNECT ON DATABASE \"{}\" TO \"{other}\"",
        f.database
    )))
    .await
    .unwrap();
    su.close().await.unwrap();
    let mut other_settings = f.settings.clone();
    let pw_file = f.dir.join("other.password");
    write_password(&pw_file, &pw);
    other_settings.migration = Some(config::DbLogin {
        user: other.clone(),
        password_file: pw_file,
    });
    let mut conn = db::connect_migration(&other_settings).await.unwrap();
    let e = db::migrate_up(&mut conn).await.unwrap_err();
    assert!(e.0.contains("is owned by"), "{e}");
    conn.close().await.unwrap();
    let mut su = admin(&f.admin_url).await;
    su.execute(sqlx::AssertSqlSafe(format!(
        "REVOKE ALL ON DATABASE \"{}\" FROM \"{other}\"",
        f.database
    )))
    .await
    .unwrap();
    su.execute(sqlx::AssertSqlSafe(format!("DROP ROLE \"{other}\"")))
        .await
        .unwrap();
    su.close().await.unwrap();
}

#[tokio::test]
async fn role_checks_follow_membership_and_function_ownership() {
    let Some(f) = Fixture::with("member", Roles::Changed).await else {
        return;
    };
    f.migrate().await;
    let database = Database::connect_runtime(&f.settings).unwrap();
    assert_eq!(db::health_check(&database).await.0, DatabaseHealth::Up);
    let mut owner = f.owner_conn().await;
    assert!(db::verify_structure(&mut owner).await.unwrap().is_empty());
    owner.close().await.unwrap();

    let side = format!("{}_side", f.owner);
    let cases: [(&str, String, &str, &str); 4] = [
        (
            "a BYPASSRLS role the runtime login can SET ROLE to",
            format!(
                "CREATE ROLE \"{side}\" NOLOGIN BYPASSRLS; GRANT \"{side}\" TO \"{}\"",
                f.runtime
            ),
            "BYPASSRLS",
            "superuser or BYPASSRLS",
        ),
        (
            "membership in the owner role, even NOINHERIT",
            format!(
                "GRANT \"{}\" TO \"{}\" WITH INHERIT FALSE",
                f.owner, f.runtime
            ),
            "owns objects",
            "login can act as",
        ),
        (
            "owning palisade.current_tenant_ids() through a role",
            format!(
                "CREATE ROLE \"{side}\" NOLOGIN; GRANT \"{side}\" TO \"{}\"; \
                 ALTER FUNCTION palisade.current_tenant_ids() OWNER TO \"{side}\"",
                f.runtime
            ),
            "owns objects",
            "login can act as",
        ),
        (
            // The cluster-wide palisade_runtime group is shared by tests that
            // run in parallel, so this goes one level down: a BYPASSRLS role
            // that the side role (granted to this test's runtime login) is a
            // member of. verify_structure walks the same chain from the
            // group's members.
            "a BYPASSRLS role two memberships away",
            format!(
                "CREATE ROLE \"{side}\" NOLOGIN; CREATE ROLE \"{side}_b\" NOLOGIN BYPASSRLS; \
                 GRANT \"{side}_b\" TO \"{side}\"; GRANT \"{side}\" TO \"{}\"",
                f.runtime
            ),
            "BYPASSRLS",
            "superuser or BYPASSRLS",
        ),
    ];
    for (what, grant, readiness_needle, verify_needle) in cases {
        let mut su = f.superuser_db_conn().await;
        for stmt in split_statements(&grant) {
            su.execute(sqlx::AssertSqlSafe(stmt)).await.unwrap();
        }
        let fresh = Database::connect_runtime(&f.settings).unwrap();
        let (state, reason) = db::health_check(&fresh).await;
        assert_eq!(state, DatabaseHealth::RoleUnsafe, "{what}: {reason}");
        assert!(reason.contains(readiness_needle), "{what}: {reason}");
        let e = db::start(&f.settings).await.unwrap_err();
        assert!(
            e.0.contains(readiness_needle),
            "{what}: serve must refuse: {e}"
        );
        fresh.close().await;
        if !verify_needle.is_empty() {
            let problems = db::verify_structure(&mut su).await.unwrap().join("\n");
            assert!(problems.contains(verify_needle), "{what}: {problems}");
        }
        // Undo.
        let undo = format!(
            "ALTER FUNCTION palisade.current_tenant_ids() OWNER TO \"{owner}\"; \
             REVOKE \"{owner}\" FROM \"{rt}\"; \
             DROP ROLE IF EXISTS \"{side}\"; DROP ROLE IF EXISTS \"{side}_b\"",
            owner = f.owner,
            rt = f.runtime,
        );
        for stmt in split_statements(&undo) {
            let _ = su.execute(sqlx::AssertSqlSafe(stmt)).await;
        }
        su.close().await.unwrap();
    }
    let again = Database::connect_runtime(&f.settings).unwrap();
    assert_eq!(db::health_check(&again).await.0, DatabaseHealth::Up);
    again.close().await;
    database.close().await;
}

#[tokio::test]
async fn serve_start_up_migrates_or_refuses() {
    let Some(f) = Fixture::new("start").await else {
        return;
    };
    // auto_migrate = false leaves the schema behind, and the server starts.
    let mut manual = f.settings.clone();
    manual.auto_migrate = false;
    let database = db::start(&manual).await.unwrap();
    assert_eq!(
        db::health_check(&database).await.0,
        DatabaseHealth::Schema(SchemaVerdict::Behind)
    );
    database.close().await;

    // auto_migrate = true applies the migrations at start.
    let mut auto = f.settings.clone();
    auto.auto_migrate = true;
    let database = db::start(&auto).await.unwrap();
    assert_eq!(db::health_check(&database).await.0, DatabaseHealth::Up);
    database.close().await;

    // A schema newer than the binary is refused, with or without
    // auto_migrate, and so is one that is newer and damaged at once.
    let mut su = f.superuser_db_conn().await;
    su.execute(
        "INSERT INTO palisade._sqlx_migrations (version, description, success, checksum, execution_time)
         VALUES (9999, 'from the future', true, '\\x00', 0)",
    )
    .await
    .unwrap();
    for settings in [&manual, &auto] {
        let e = db::start(settings).await.unwrap_err();
        assert!(e.0.contains("newer than this binary"), "{e}");
    }
    su.execute("UPDATE palisade._sqlx_migrations SET checksum = '\\x00' WHERE version = 1")
        .await
        .unwrap();
    for settings in [&manual, &auto] {
        let e = db::start(settings).await.unwrap_err();
        assert!(
            e.0.contains("newer than this binary") || e.0.contains("migrate verify"),
            "{e}"
        );
    }
    su.close().await.unwrap();
}

#[tokio::test]
async fn serve_refuses_a_login_outside_the_runtime_group_on_a_migrated_database() {
    let Some(f) = Fixture::with("outsider", Roles::Changed).await else {
        return;
    };
    f.migrate().await;
    // Two logins that cannot read the schema at all, because neither is in
    // palisade_runtime: a plain one, and one with BYPASSRLS. Both must be
    // refused as unsafe, not treated as an unreachable database.
    for (suffix, attrs, needle) in [
        ("plain", "", "is not a member of palisade_runtime"),
        ("bypass", "BYPASSRLS", "BYPASSRLS"),
    ] {
        let user = format!("{}_{suffix}", f.owner);
        let pw = password();
        let mut su = admin(&f.admin_url).await;
        su.execute(sqlx::AssertSqlSafe(format!(
            "CREATE ROLE \"{user}\" LOGIN {attrs} PASSWORD '{pw}'"
        )))
        .await
        .unwrap();
        su.execute(sqlx::AssertSqlSafe(format!(
            "GRANT CONNECT ON DATABASE \"{}\" TO \"{user}\"",
            f.database
        )))
        .await
        .unwrap();
        let pw_file = f.dir.join(format!("{suffix}.password"));
        write_password(&pw_file, &pw);
        let mut settings = f.settings.clone();
        settings.runtime = config::DbLogin {
            user: user.clone(),
            password_file: pw_file,
        };
        settings.auto_migrate = false;
        let e = db::start(&settings).await.unwrap_err();
        assert!(e.0.contains(needle), "{suffix}: {e}");
        su.execute(sqlx::AssertSqlSafe(format!(
            "REVOKE ALL ON DATABASE \"{}\" FROM \"{user}\"",
            f.database
        )))
        .await
        .unwrap();
        su.close().await.unwrap();
    }
}

#[tokio::test]
async fn serve_starts_not_ready_when_the_database_is_unreachable() {
    // Needs no Postgres: nothing listens on the port.
    let dir = common::temp_dir("pg-start-down");
    write_password(&dir.join("runtime.password"), "unused");
    write_password(&dir.join("owner.password"), "unused");
    let port = common::free_port();
    let settings = db_settings(
        &format!(
            "[database]\nhost = \"127.0.0.1\"\nport = {port}\nname = \"p\"\nuser = \"app\"\n\
             password_file = \"runtime.password\"\ntls = \"disable\"\nconnect_timeout_secs = 1\n\
             [database.migration]\nuser = \"owner\"\npassword_file = \"owner.password\"\n"
        ),
        &dir,
    );
    assert!(settings.auto_migrate);
    let inherited = inherited_refused_env();
    if !inherited.is_empty() {
        let e = db::start(&settings).await.unwrap_err();
        assert_refused_for(&e, &inherited);
        return;
    }
    let database = db::start(&settings).await.unwrap();
    assert_eq!(db::health_check(&database).await.0, DatabaseHealth::Down);
    database.close().await;
}

#[cfg(unix)]
#[test]
fn check_config_checks_the_database_files() {
    // Needs no Postgres. check-config and serve read the password files and
    // the CA file before binding, and report problems as config errors.
    use std::os::unix::fs::PermissionsExt;
    let pki = common::pki("pg-check", &["localhost"]);
    let dir = &pki.dir;
    write_password(&dir.join("runtime.password"), "pw");
    let body = |extra: &str| {
        format!(
            "[listen.admin]\nbind = \"127.0.0.1\"\nport = 1\n\
             [listen.agent]\nbind = \"127.0.0.1\"\nport = 2\nclient_ca_file = \"agent-ca.crt\"\n\
             [database]\nhost = \"127.0.0.1\"\nname = \"p\"\nuser = \"app\"\n\
             password_file = \"runtime.password\"\n{extra}"
        )
    };
    let check = |extra: &str| {
        let path = common::write_config(&pki, &body(extra));
        let out = Command::new(BIN)
            .args(["check-config", "-c", path.to_str().unwrap()])
            .env_remove("PGPASSWORD")
            .output()
            .unwrap();
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    let (code, err) = check("tls = \"disable\"\n");
    assert_eq!(code, Some(0), "{err}");

    std::fs::set_permissions(
        dir.join("runtime.password"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let (code, err) = check("tls = \"disable\"\n");
    assert_eq!(code, Some(2), "{err}");
    assert!(
        err.contains("database.password_file") && err.contains("chmod 600"),
        "{err}"
    );
    std::fs::set_permissions(
        dir.join("runtime.password"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();

    std::fs::write(dir.join("empty-ca.pem"), "# no certificates here\n").unwrap();
    let (code, err) = check("ca_file = \"empty-ca.pem\"\n");
    assert_eq!(code, Some(2), "{err}");
    assert!(
        err.contains("database.ca_file") && err.contains("no PEM certificates"),
        "{err}"
    );

    let (code, err) = check(
        "tls = \"disable\"\n[database.migration]\nuser = \"owner\"\npassword_file = \"missing.password\"\n",
    );
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains("database.migration.password_file"), "{err}");

    let path = common::write_config(&pki, &body("tls = \"disable\"\n"));
    let out = Command::new(BIN)
        .args(["check-config", "-c", path.to_str().unwrap()])
        .env("PGOPTIONS", "-c row_security=off")
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{err}");
    assert!(err.contains("PGOPTIONS"), "{err}");
}
