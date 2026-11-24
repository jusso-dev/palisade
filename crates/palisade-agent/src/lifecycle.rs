//! The agent's operating states and the legal transitions between them.
//!
//! | From | To |
//! |---|---|
//! | `Starting` | `Running`, `Degraded`, `SafeMode`, `FailSafe`, `Stopping` |
//! | `Running` | `Degraded`, `Updating`, `FailSafe`, `Stopping` |
//! | `Degraded` | `Running`, `Degraded` (new reasons), `Updating`, `FailSafe`, `Stopping` |
//! | `Updating` | `Running`, `Degraded`, `FailSafe`, `Stopping` |
//! | `SafeMode` | `FailSafe`, `Stopping` |
//! | `FailSafe` | `FailSafe` (new reason), `Stopping` |
//! | `Stopping` | `Stopped` |
//! | `Stopped` | nothing |
//!
//! `FailSafe` is left only by stopping: a critical subsystem that reached it
//! is not restarted again until the service restarts. What enforcement does
//! in that state is governed by [`FailMode`](crate::config::FailMode). Safe
//! mode lasts for the whole boot. The supervisor drives `Starting`,
//! `Running`, `Degraded`, `FailSafe`, `Stopping` and `Stopped`. `SafeMode`
//! (safe-boot detection) and `Updating` (#66) are entered by the components
//! that own them when they land.

use std::fmt;

/// An agent operating state, as exposed in health and events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentState {
    /// Subsystems are being started for the first time.
    Starting,
    /// Every subsystem is running.
    Running,
    /// The agent works, but some subsystems are not running, with the reasons.
    Degraded(Vec<String>),
    /// Windows was booted in safe mode; see
    /// [`SafeModeBehaviour`](crate::config::SafeModeBehaviour).
    SafeMode,
    /// An agent update is being applied.
    Updating,
    /// Subsystems are being stopped.
    Stopping,
    /// Every subsystem has stopped.
    Stopped,
    /// An internal error forced the fail-safe state, with the reason.
    FailSafe(String),
}

impl AgentState {
    /// Whether moving from `self` to `next` is allowed (see the module table).
    /// Staying in the same state is always allowed and is a no-op.
    pub fn can_transition_to(&self, next: &AgentState) -> bool {
        use AgentState::*;
        self == next
            || matches!(
                (self, next),
                (
                    Starting,
                    Running | Degraded(_) | SafeMode | FailSafe(_) | Stopping
                ) | (Running, Degraded(_) | Updating | FailSafe(_) | Stopping)
                    | (
                        Degraded(_),
                        Running | Degraded(_) | Updating | FailSafe(_) | Stopping
                    )
                    | (Updating, Running | Degraded(_) | FailSafe(_) | Stopping)
                    | (SafeMode, FailSafe(_) | Stopping)
                    | (FailSafe(_), FailSafe(_) | Stopping)
                    | (Stopping, Stopped)
            )
    }
}

impl fmt::Display for AgentState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Starting => f.write_str("starting"),
            Self::Running => f.write_str("running"),
            Self::Degraded(reasons) => write!(f, "degraded ({})", reasons.join("; ")),
            Self::SafeMode => f.write_str("safe mode"),
            Self::Updating => f.write_str("updating"),
            Self::Stopping => f.write_str("stopping"),
            Self::Stopped => f.write_str("stopped"),
            Self::FailSafe(reason) => write!(f, "fail-safe ({reason})"),
        }
    }
}

/// A rejected state change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IllegalTransition {
    /// The current state.
    pub from: AgentState,
    /// The requested state.
    pub to: AgentState,
}

impl fmt::Display for IllegalTransition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "illegal agent state change: {} -> {}",
            self.from, self.to
        )
    }
}

impl std::error::Error for IllegalTransition {}

/// The current agent state, changed only through legal transitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lifecycle {
    state: AgentState,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl Lifecycle {
    /// A lifecycle in [`AgentState::Starting`].
    pub fn new() -> Self {
        Self {
            state: AgentState::Starting,
        }
    }

    /// The current state.
    pub fn state(&self) -> &AgentState {
        &self.state
    }

    /// Moves to `next`. Returns the previous state if the state changed,
    /// `None` if `next` equals the current state. An illegal transition
    /// leaves the state unchanged.
    pub fn transition(
        &mut self,
        next: AgentState,
    ) -> Result<Option<AgentState>, IllegalTransition> {
        if self.state == next {
            return Ok(None);
        }
        if !self.state.can_transition_to(&next) {
            return Err(IllegalTransition {
                from: self.state.clone(),
                to: next,
            });
        }
        Ok(Some(std::mem::replace(&mut self.state, next)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use AgentState::*;

    fn all() -> Vec<AgentState> {
        vec![
            Starting,
            Running,
            Degraded(vec!["a".into()]),
            SafeMode,
            Updating,
            Stopping,
            Stopped,
            FailSafe("x".into()),
        ]
    }

    #[test]
    fn transition_table() {
        let allowed: &[(&str, &[&str])] = &[
            (
                "starting",
                &["running", "degraded", "safe", "fail", "stopping"],
            ),
            ("running", &["degraded", "updating", "fail", "stopping"]),
            (
                "degraded",
                &["running", "degraded", "updating", "fail", "stopping"],
            ),
            ("safe", &["fail", "stopping"]),
            ("updating", &["running", "degraded", "fail", "stopping"]),
            ("stopping", &["stopped"]),
            ("stopped", &[]),
            ("fail", &["fail", "stopping"]),
        ];
        let label = |s: &AgentState| match s {
            Starting => "starting",
            Running => "running",
            Degraded(_) => "degraded",
            SafeMode => "safe",
            Updating => "updating",
            Stopping => "stopping",
            Stopped => "stopped",
            FailSafe(_) => "fail",
        };
        for from in all() {
            let (_, targets) = allowed.iter().find(|(l, _)| *l == label(&from)).unwrap();
            for to in all() {
                // Same-kind changes with a different payload.
                let to = match (&from, to) {
                    (Degraded(_), Degraded(_)) => Degraded(vec!["b".into()]),
                    (FailSafe(_), FailSafe(_)) => FailSafe("y".into()),
                    (_, to) => to,
                };
                let expected = from == to || targets.contains(&label(&to));
                assert_eq!(from.can_transition_to(&to), expected, "{from} -> {to}");
            }
        }
    }

    #[test]
    fn lifecycle_applies_legal_and_rejects_illegal() {
        let mut life = Lifecycle::new();
        assert_eq!(life.state(), &Starting);
        assert_eq!(life.transition(Starting), Ok(None));
        assert_eq!(life.transition(Running), Ok(Some(Starting)));
        assert_eq!(
            life.transition(Stopped),
            Err(IllegalTransition {
                from: Running,
                to: Stopped
            })
        );
        assert_eq!(life.state(), &Running);
        assert_eq!(life.transition(FailSafe("bug".into())), Ok(Some(Running)));
        assert!(life.transition(Running).is_err());
        assert_eq!(life.transition(Stopping), Ok(Some(FailSafe("bug".into()))));
        assert_eq!(life.transition(Stopped), Ok(Some(Stopping)));
        for next in all() {
            if next != Stopped {
                assert!(life.transition(next).is_err());
            }
        }
    }
}
