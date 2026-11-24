//! Process health, as reported by the liveness and readiness probes.
//!
//! - `/healthz` (liveness) answers 200 whenever the process can serve a
//!   request at all.
//! - `/readyz` (readiness) answers 200 when every configured listener is
//!   bound on every address it should be, and the server is not shutting
//!   down. Otherwise it answers 503. The body is a small JSON document with
//!   a `status` and a list of `indicators`. It carries no addresses.
//!
//! Indicators:
//!
//! | Indicator | Meaning | Readiness |
//! |---|---|---|
//! | `listener_unbound:<name>` | The listener has an address it could not bind yet, or a named interface with no address | 503 |
//! | `public_exposure:<name>` | `deployment.profile = "overlay"` and the listener is reachable on a public address | 200, status `degraded` |
//! | `shutting_down` | Shutdown has started and connections are draining | 503 |
//! | `database_down` | `[database]` is configured and the last check could not reach it as the runtime role | 503 |
//! | `database_schema:<verdict>` | The schema is `behind` (pending migrations), `newer` than this binary, or `damaged` (checksum mismatch or a failed migration) | 503 |
//! | `database_role_unsafe` | The runtime login could bypass row-level security (superuser, `BYPASSRLS`, owns schema objects) | 503 |
//!
//! Job runner readiness joins this list with the job runner work in #126.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::{Mutex, MutexGuard, PoisonError};

use serde_json::{Value, json};

use crate::config::ListenerKind;
use crate::db::SchemaVerdict;

/// Health of one listener.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListenerHealth {
    /// Local addresses currently accepting connections.
    pub bound: BTreeSet<SocketAddr>,
    /// Whether some wanted address is not bound yet.
    pub unbound: bool,
    /// Whether the listener is reachable on a public address under the
    /// overlay profile.
    pub public_exposure: bool,
}

/// Health of the database, as seen by the last check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseHealth {
    /// Not checked yet, or the last check could not connect or query.
    Down,
    /// Reachable, the schema matches this binary and the role is safe.
    Up,
    /// Reachable, but the schema does not match this binary.
    Schema(SchemaVerdict),
    /// Reachable, but the runtime login could bypass row-level security.
    RoleUnsafe,
}

#[derive(Debug, Default)]
struct Inner {
    listeners: BTreeMap<ListenerKind, ListenerHealth>,
    shutting_down: bool,
    /// `None` when no database is configured.
    database: Option<DatabaseHealth>,
}

/// Shared, thread-safe health state.
#[derive(Debug, Default)]
pub struct Health {
    inner: Mutex<Inner>,
}

/// A readiness verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Readiness {
    /// Whether the probe should pass.
    pub ready: bool,
    /// The JSON body.
    pub body: Value,
}

impl Health {
    /// Health with every listener in `kinds` registered as unbound.
    pub fn new(kinds: impl IntoIterator<Item = ListenerKind>) -> Self {
        let listeners = kinds
            .into_iter()
            .map(|k| {
                (
                    k,
                    ListenerHealth {
                        unbound: true,
                        ..ListenerHealth::default()
                    },
                )
            })
            .collect();
        Self {
            inner: Mutex::new(Inner {
                listeners,
                shutting_down: false,
                database: None,
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // The state is plain data, valid after any panic, so a poisoned
        // lock is still usable.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Records the current state of one listener.
    pub fn set_listener(&self, kind: ListenerKind, state: ListenerHealth) {
        self.lock().listeners.insert(kind, state);
    }

    /// The recorded state of one listener.
    pub fn listener(&self, kind: ListenerKind) -> Option<ListenerHealth> {
        self.lock().listeners.get(&kind).cloned()
    }

    /// Records the database state. Once set, the database counts towards
    /// readiness.
    pub fn set_database(&self, state: DatabaseHealth) {
        self.lock().database = Some(state);
    }

    /// The recorded database state, or `None` if no database is configured.
    pub fn database(&self) -> Option<DatabaseHealth> {
        self.lock().database
    }

    /// Marks the start of shutdown. Readiness fails from now on.
    pub fn set_shutting_down(&self) {
        self.lock().shutting_down = true;
    }

    /// The readiness verdict and body.
    pub fn readiness(&self) -> Readiness {
        let inner = self.lock();
        let mut indicators = Vec::new();
        let mut ready = true;
        let mut degraded = false;
        if inner.shutting_down {
            ready = false;
            indicators.push("shutting_down".to_owned());
        }
        for (kind, l) in &inner.listeners {
            if l.unbound {
                ready = false;
                indicators.push(format!("listener_unbound:{kind}"));
            }
            if l.public_exposure {
                degraded = true;
                indicators.push(format!("public_exposure:{kind}"));
            }
        }
        match inner.database {
            None | Some(DatabaseHealth::Up) => {}
            Some(DatabaseHealth::Down) => {
                ready = false;
                indicators.push("database_down".to_owned());
            }
            Some(DatabaseHealth::Schema(verdict)) => {
                ready = false;
                indicators.push(format!("database_schema:{}", verdict.as_str()));
            }
            Some(DatabaseHealth::RoleUnsafe) => {
                ready = false;
                indicators.push("database_role_unsafe".to_owned());
            }
        }
        let status = if inner.shutting_down {
            "shutting_down"
        } else if !ready || degraded {
            "degraded"
        } else {
            "ready"
        };
        Readiness {
            ready,
            body: json!({ "status": status, "indicators": indicators }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_listeners_start_unbound() {
        let h = Health::new([ListenerKind::Admin, ListenerKind::Agent]);
        let r = h.readiness();
        assert!(!r.ready);
        assert_eq!(r.body["status"], "degraded");
        assert_eq!(
            r.body["indicators"],
            json!(["listener_unbound:admin", "listener_unbound:agent"])
        );
    }

    #[test]
    fn ready_when_all_bound() {
        let h = Health::new([ListenerKind::Admin]);
        h.set_listener(ListenerKind::Admin, ListenerHealth::default());
        let r = h.readiness();
        assert!(r.ready);
        assert_eq!(r.body, json!({ "status": "ready", "indicators": [] }));
    }

    #[test]
    fn public_exposure_degrades_but_stays_ready() {
        let h = Health::new([ListenerKind::Admin]);
        h.set_listener(
            ListenerKind::Admin,
            ListenerHealth {
                public_exposure: true,
                ..ListenerHealth::default()
            },
        );
        let r = h.readiness();
        assert!(r.ready);
        assert_eq!(r.body["status"], "degraded");
        assert_eq!(r.body["indicators"], json!(["public_exposure:admin"]));
    }

    #[test]
    fn database_states() {
        let h = Health::new([ListenerKind::Admin]);
        h.set_listener(ListenerKind::Admin, ListenerHealth::default());
        assert!(h.readiness().ready, "no database configured");
        for (state, indicator) in [
            (DatabaseHealth::Down, "database_down"),
            (
                DatabaseHealth::Schema(SchemaVerdict::Behind),
                "database_schema:behind",
            ),
            (
                DatabaseHealth::Schema(SchemaVerdict::Newer),
                "database_schema:newer",
            ),
            (
                DatabaseHealth::Schema(SchemaVerdict::Damaged),
                "database_schema:damaged",
            ),
            (DatabaseHealth::RoleUnsafe, "database_role_unsafe"),
        ] {
            h.set_database(state);
            let r = h.readiness();
            assert!(!r.ready, "{indicator}");
            assert_eq!(r.body["indicators"], json!([indicator]));
        }
        h.set_database(DatabaseHealth::Up);
        assert_eq!(
            h.readiness().body,
            json!({ "status": "ready", "indicators": [] })
        );
    }

    #[test]
    fn shutting_down_is_not_ready() {
        let h = Health::new([ListenerKind::Admin]);
        h.set_listener(ListenerKind::Admin, ListenerHealth::default());
        h.set_shutting_down();
        let r = h.readiness();
        assert!(!r.ready);
        assert_eq!(r.body["status"], "shutting_down");
    }
}
