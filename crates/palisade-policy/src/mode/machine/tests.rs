//! Tests of the mode state machine (#36): the transition table, the
//! time-box rules, expiry under clock rollback, and random sequences.

use proptest::prelude::*;

use super::*;
use crate::mode::strictness;

const ALL: [Mode; 5] = [
    Mode::Disabled,
    Mode::Monitor,
    Mode::Audit,
    Mode::Learning,
    Mode::Enforce,
];

const DAY: i64 = 86_400;

/// A simulated pair of clocks. The wall clock can be set anywhere; the
/// monotonic clock only advances.
#[derive(Clone, Copy, Debug)]
struct SimClock {
    wall: i64,
    monotonic: u64,
}

impl SimClock {
    const fn start() -> Self {
        Self {
            wall: 1_800_000_000,
            monotonic: 1_000,
        }
    }

    fn advance(&mut self, secs: u64) {
        self.monotonic += secs;
        self.wall += i64::try_from(secs).unwrap();
    }
}

impl Clock for SimClock {
    fn now(&self) -> Now {
        Now {
            wall_secs: self.wall,
            monotonic_secs: self.monotonic,
        }
    }
}

/// A request with every field a weakening change needs.
fn full(to: Mode, now: Now, secs: i64) -> Request {
    Request {
        reason: Some("pilot".to_owned()),
        ticket: Some("CHG-1".to_owned()),
        expires_at: Some(now.wall_secs + secs),
        ..Request::new(to, "admin")
    }
}

/// The smallest valid request from `from` to `to`.
fn minimal(from: Mode, to: Mode, now: Now) -> Request {
    if needs_time_box(from, to) {
        full(to, now, DAY)
    } else {
        Request::new(to, "admin")
    }
}

/// The table in the issue, written out.
const LEGAL: [(Mode, &[Mode]); 5] = [
    (
        Mode::Disabled,
        &[Mode::Monitor, Mode::Audit, Mode::Learning, Mode::Enforce],
    ),
    (
        Mode::Monitor,
        &[Mode::Audit, Mode::Learning, Mode::Enforce, Mode::Disabled],
    ),
    (
        Mode::Audit,
        &[Mode::Learning, Mode::Enforce, Mode::Monitor, Mode::Disabled],
    ),
    (
        Mode::Learning,
        &[Mode::Audit, Mode::Enforce, Mode::Disabled],
    ),
    (
        Mode::Enforce,
        &[Mode::Audit, Mode::Learning, Mode::Monitor, Mode::Disabled],
    ),
];

#[test]
fn the_transition_table_is_exactly_the_issue_table() {
    let now = SimClock::start().now();
    for (from, targets) in LEGAL {
        for to in ALL {
            let legal = targets.contains(&to);
            assert_eq!(is_legal(from, to), legal, "{from:?} -> {to:?}");
            let mut m = ModeMachine::new(from);
            let result = m.transition(&minimal(from, to, now), &Governance::default(), now);
            if legal {
                let changes = result.unwrap();
                assert_eq!(changes.len(), 1);
                assert_eq!((changes[0].old, changes[0].new), (from, to));
                assert_eq!(m.stored(), to);
            } else {
                let expected = if from == to {
                    TransitionError::SameMode
                } else {
                    TransitionError::Illegal { from, to }
                };
                assert_eq!(result, Err(expected));
                assert_eq!(m, ModeMachine::new(from));
            }
        }
    }
}

#[test]
fn leaving_enforce_needs_a_reason_a_ticket_and_an_expiry() {
    let now = SimClock::start().now();
    let strict = Governance {
        require_ticket: true,
        may_weaken_permanently: false,
    };
    for to in [Mode::Audit, Mode::Learning, Mode::Monitor, Mode::Disabled] {
        let ok = full(to, now, DAY);
        let cases = [
            (
                Request {
                    reason: None,
                    ..ok.clone()
                },
                TransitionError::ReasonRequired,
            ),
            (
                Request {
                    reason: Some("  ".to_owned()),
                    ..ok.clone()
                },
                TransitionError::ReasonRequired,
            ),
            (
                Request {
                    ticket: None,
                    ..ok.clone()
                },
                TransitionError::TicketRequired,
            ),
            (
                Request {
                    expires_at: None,
                    ..ok.clone()
                },
                TransitionError::ExpiryRequired,
            ),
            (
                Request {
                    expires_at: Some(now.wall_secs),
                    ..ok.clone()
                },
                TransitionError::ExpiryInPast,
            ),
            (
                Request {
                    expires_at: Some(now.wall_secs + MAX_TIME_BOX_SECS + 1),
                    ..ok.clone()
                },
                TransitionError::ExpiryTooFar,
            ),
            (
                Request {
                    expires_at: None,
                    permanent: true,
                    ..ok.clone()
                },
                TransitionError::PermanentNotAllowed,
            ),
        ];
        for (request, error) in cases {
            let mut m = ModeMachine::new(Mode::Enforce);
            assert_eq!(m.transition(&request, &strict, now), Err(error), "{to:?}");
            assert_eq!(m, ModeMachine::new(Mode::Enforce));
        }
        // Without the tenant's ticket rule, no ticket is needed.
        let mut m = ModeMachine::new(Mode::Enforce);
        let no_ticket = Request {
            ticket: None,
            ..ok.clone()
        };
        m.transition(&no_ticket, &Governance::default(), now)
            .unwrap();
        // Exactly 30 days is allowed.
        let mut m = ModeMachine::new(Mode::Enforce);
        let changes = m
            .transition(&full(to, now, MAX_TIME_BOX_SECS), &strict, now)
            .unwrap();
        assert_eq!(
            changes[0].expires_at,
            Some(now.wall_secs + MAX_TIME_BOX_SECS)
        );
        let b = m.time_box().unwrap();
        assert_eq!(b.prior, Mode::Enforce);
        assert_eq!(b.budget_secs, MAX_TIME_BOX_SECS.unsigned_abs());
    }
}

#[test]
fn entering_disabled_is_always_time_boxed() {
    let now = SimClock::start().now();
    for from in [Mode::Monitor, Mode::Audit, Mode::Learning] {
        let mut m = ModeMachine::new(from);
        assert_eq!(
            m.transition(
                &Request::new(Mode::Disabled, "admin"),
                &Governance::default(),
                now
            ),
            Err(TransitionError::ReasonRequired)
        );
        m.transition(&full(Mode::Disabled, now, DAY), &Governance::default(), now)
            .unwrap();
        assert_eq!(m.time_box().unwrap().prior, from);
    }
}

#[test]
fn only_enforce_to_audit_can_be_permanent_and_only_with_the_permission() {
    let now = SimClock::start().now();
    let elevated = Governance {
        require_ticket: false,
        may_weaken_permanently: true,
    };
    let permanent = |to| Request {
        reason: Some("steady state".to_owned()),
        permanent: true,
        ..Request::new(to, "admin")
    };
    let mut m = ModeMachine::new(Mode::Enforce);
    let changes = m
        .transition(&permanent(Mode::Audit), &elevated, now)
        .unwrap();
    assert_eq!(changes[0].expires_at, None);
    assert_eq!(m.time_box(), None);
    assert_eq!(m.current(now), Mode::Audit);

    for to in [Mode::Learning, Mode::Monitor, Mode::Disabled] {
        let mut m = ModeMachine::new(Mode::Enforce);
        assert_eq!(
            m.transition(&permanent(to), &elevated, now),
            Err(TransitionError::PermanentNotAllowed)
        );
    }
    // Permanent and an expiry together are contradictory.
    let both = Request {
        expires_at: Some(now.wall_secs + DAY),
        ..permanent(Mode::Audit)
    };
    assert_eq!(
        ModeMachine::new(Mode::Enforce).transition(&both, &elevated, now),
        Err(TransitionError::PermanentNotAllowed)
    );
    // A change that is not time-boxed cannot carry an expiry.
    assert_eq!(
        ModeMachine::new(Mode::Audit).transition(
            &full(Mode::Enforce, now, DAY),
            &Governance::default(),
            now
        ),
        Err(TransitionError::TimeBoxNotAllowed)
    );
}

#[test]
fn a_time_box_reverts_on_the_wall_clock() {
    let mut clock = SimClock::start();
    let mut m = ModeMachine::new(Mode::Enforce);
    m.transition(
        &full(Mode::Audit, clock.now(), 3_600),
        &Governance::default(),
        clock.now(),
    )
    .unwrap();
    clock.advance(3_599);
    assert_eq!(m.current(clock.now()), Mode::Audit);
    assert_eq!(m.tick(clock.now()), None);
    clock.advance(1);
    assert_eq!(m.current(clock.now()), Mode::Enforce);
    let change = m.tick(clock.now()).unwrap();
    assert_eq!(
        (change.old, change.new, change.cause),
        (Mode::Audit, Mode::Enforce, Cause::Expired)
    );
    assert_eq!(change.actor, None);
    assert_eq!(m, ModeMachine::new(Mode::Enforce));
}

#[test]
fn setting_the_wall_clock_back_does_not_extend_a_time_box() {
    let mut clock = SimClock::start();
    let mut m = ModeMachine::new(Mode::Enforce);
    m.transition(
        &full(Mode::Monitor, clock.now(), 3_600),
        &Governance::default(),
        clock.now(),
    )
    .unwrap();
    // Half an hour in, the clock is set back a year, again and again.
    for _ in 0..5 {
        clock.advance(600);
        clock.wall -= 365 * DAY;
    }
    assert_eq!(clock.monotonic - 1_000, 3_000);
    assert_eq!(m.current(clock.now()), Mode::Monitor);
    clock.advance(600);
    // The monotonic budget has run out, whatever the wall clock says.
    assert_eq!(m.current(clock.now()), Mode::Enforce);
    assert_eq!(m.tick(clock.now()).unwrap().new, Mode::Enforce);
}

#[test]
fn setting_the_wall_clock_forward_only_ends_a_time_box_early() {
    let mut clock = SimClock::start();
    let mut m = ModeMachine::new(Mode::Enforce);
    m.transition(
        &full(Mode::Learning, clock.now(), 7 * DAY),
        &Governance::default(),
        clock.now(),
    )
    .unwrap();
    clock.wall += 8 * DAY;
    assert_eq!(m.current(clock.now()), Mode::Enforce);
}

#[test]
fn a_monotonic_clock_that_restarted_ends_a_time_box() {
    let clock = SimClock::start();
    let mut m = ModeMachine::new(Mode::Enforce);
    m.transition(
        &full(Mode::Audit, clock.now(), DAY),
        &Governance::default(),
        clock.now(),
    )
    .unwrap();
    let restarted = Now {
        wall_secs: clock.wall + 60,
        monotonic_secs: 5,
    };
    assert_eq!(m.current(restarted), Mode::Enforce);
}

#[test]
fn changes_inside_a_time_box_keep_or_end_it() {
    let mut clock = SimClock::start();
    let g = Governance::default();
    let mut m = ModeMachine::new(Mode::Enforce);
    m.transition(&full(Mode::Audit, clock.now(), DAY), &g, clock.now())
        .unwrap();
    // Audit -> monitor is still weaker than the target: it needs a reason,
    // keeps the box, and cannot set an expiry of its own.
    assert_eq!(
        m.transition(&Request::new(Mode::Monitor, "admin"), &g, clock.now()),
        Err(TransitionError::ReasonRequired)
    );
    assert_eq!(
        m.transition(&full(Mode::Monitor, clock.now(), DAY), &g, clock.now()),
        Err(TransitionError::TimeBoxNotAllowed)
    );
    let monitor = Request {
        reason: Some("quieter".to_owned()),
        ..Request::new(Mode::Monitor, "admin")
    };
    let changes = m.transition(&monitor, &g, clock.now()).unwrap();
    assert_eq!(changes[0].expires_at, Some(clock.wall + DAY));
    assert_eq!(m.time_box().unwrap().prior, Mode::Enforce);
    // Expiry still returns to enforce.
    clock.advance(86_400);
    let changes = m
        .transition(&Request::new(Mode::Audit, "admin"), &g, clock.now())
        .map(|c| c.into_iter().map(|c| (c.old, c.new)).collect::<Vec<_>>());
    // The expiry happens first, and then enforce -> audit needs a box.
    assert_eq!(changes, Err(TransitionError::ReasonRequired));
    assert_eq!(m.current(clock.now()), Mode::Enforce);

    // Returning to enforce ends the box.
    let mut m = ModeMachine::new(Mode::Enforce);
    m.transition(&full(Mode::Audit, clock.now(), DAY), &g, clock.now())
        .unwrap();
    m.transition(&Request::new(Mode::Enforce, "admin"), &g, clock.now())
        .unwrap();
    assert_eq!(m, ModeMachine::new(Mode::Enforce));
}

#[test]
fn an_expiry_is_reported_before_the_requested_change() {
    let mut clock = SimClock::start();
    let g = Governance::default();
    let mut m = ModeMachine::new(Mode::Audit);
    m.transition(&full(Mode::Disabled, clock.now(), 60), &g, clock.now())
        .unwrap();
    clock.advance(61);
    let changes = m
        .transition(&Request::new(Mode::Learning, "admin"), &g, clock.now())
        .unwrap();
    let pairs: Vec<_> = changes.iter().map(|c| (c.old, c.new, c.cause)).collect();
    assert_eq!(
        pairs,
        [
            (Mode::Disabled, Mode::Audit, Cause::Expired),
            (Mode::Audit, Mode::Learning, Cause::Requested),
        ]
    );
}

#[test]
fn a_request_needs_an_actor() {
    let now = SimClock::start().now();
    let mut m = ModeMachine::new(Mode::Audit);
    assert_eq!(
        m.transition(
            &Request::new(Mode::Enforce, "  "),
            &Governance::default(),
            now
        ),
        Err(TransitionError::ActorRequired)
    );
    assert_eq!(m, ModeMachine::new(Mode::Audit));
}

#[test]
fn leaving_learning_is_flagged_for_the_summary() {
    let now = SimClock::start().now();
    let mut m = ModeMachine::new(Mode::Learning);
    let changes = m
        .transition(
            &Request::new(Mode::Enforce, "admin"),
            &Governance::default(),
            now,
        )
        .unwrap();
    assert!(changes[0].learning_ended);
    let mut m = ModeMachine::new(Mode::Audit);
    let changes = m
        .transition(
            &Request::new(Mode::Enforce, "admin"),
            &Governance::default(),
            now,
        )
        .unwrap();
    assert!(!changes[0].learning_ended);
}

/// One step of a random history.
#[derive(Clone, Debug)]
enum Step {
    /// Time passes on both clocks.
    Advance(u64),
    /// The wall clock is set by this many seconds (either way).
    SetWall(i64),
    /// The agent restarts: the monotonic clock starts again from a value.
    Restart(u64),
    /// A request, with an expiry this many seconds from now.
    Request {
        to: Mode,
        reason: bool,
        ticket: bool,
        expires_in: Option<i64>,
        permanent: bool,
    },
    /// The agent checks for expiry.
    Tick,
}

fn step() -> impl Strategy<Value = Step> {
    let mode = proptest::sample::select(ALL.to_vec());
    prop_oneof![
        (0u64..200_000).prop_map(Step::Advance),
        (-40 * DAY..40 * DAY).prop_map(Step::SetWall),
        (0u64..100).prop_map(Step::Restart),
        (
            mode,
            any::<bool>(),
            any::<bool>(),
            proptest::option::of(-DAY..40 * DAY),
            proptest::bool::weighted(0.1),
        )
            .prop_map(
                |(to, reason, ticket, expires_in, permanent)| Step::Request {
                    to,
                    reason,
                    ticket,
                    expires_in,
                    permanent
                }
            ),
        Just(Step::Tick),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    /// Random histories of requests, ticks and clock changes (including the
    /// wall clock set back and agent restarts) never produce a change
    /// outside the legal table, never leave `enforce` without a time box
    /// (or a permitted permanent move to `audit`), and never keep a
    /// weaker mode past its monotonic budget.
    #[test]
    fn no_history_reaches_an_illegal_state(
        start in proptest::sample::select(ALL.to_vec()),
        steps in proptest::collection::vec(step(), 1..40),
        governance in (any::<bool>(), any::<bool>()).prop_map(|(t, p)| Governance {
            require_ticket: t,
            may_weaken_permanently: p,
        }),
    ) {
        let mut clock = SimClock::start();
        let mut m = ModeMachine::new(start);
        for step in steps {
            let before = m;
            let changes = match step {
                Step::Advance(s) => { clock.advance(s); Vec::new() }
                Step::SetWall(d) => { clock.wall += d; Vec::new() }
                Step::Restart(at) => { clock.monotonic = at; Vec::new() }
                Step::Tick => m.tick(clock.now()).into_iter().collect(),
                Step::Request { to, reason, ticket, expires_in, permanent } => {
                    let request = Request {
                        to,
                        actor: "admin".to_owned(),
                        reason: reason.then(|| "why".to_owned()),
                        ticket: ticket.then(|| "CHG-9".to_owned()),
                        expires_at: expires_in.map(|s| clock.wall + s),
                        permanent,
                    };
                    match m.transition(&request, &governance, clock.now()) {
                        Ok(changes) => {
                            let last = changes.last().unwrap();
                            prop_assert_eq!(last.new, to);
                            prop_assert_eq!(last.cause, Cause::Requested);
                            if needs_time_box(last.old, to) {
                                prop_assert!(reason);
                                prop_assert!(!governance.require_ticket || ticket);
                            }
                            changes
                        }
                        Err(_) => {
                            prop_assert_eq!(m, before);
                            Vec::new()
                        }
                    }
                }
            };
            let mut previous = before.stored();
            for c in &changes {
                prop_assert_eq!(c.old, previous);
                prop_assert!(is_legal(c.old, c.new), "{:?} -> {:?}", c.old, c.new);
                previous = c.new;
            }
            prop_assert_eq!(previous, m.stored());
            // While a box runs, the mode is weaker than its target, and the
            // box ends within its budget on the monotonic clock.
            if let Some(b) = m.time_box() {
                prop_assert!(strictness(m.stored()) < strictness(b.prior));
                prop_assert!(b.budget_secs <= MAX_TIME_BOX_SECS.unsigned_abs());
                let late = Now {
                    wall_secs: i64::MIN,
                    monotonic_secs: b.started_monotonic + b.budget_secs,
                };
                prop_assert_eq!(m.current(late), b.prior);
            } else if before.stored() == Mode::Enforce && m.stored() != Mode::Enforce {
                // Leaving enforce with no box: only the permitted
                // permanent move to audit.
                prop_assert_eq!(m.stored(), Mode::Audit);
                prop_assert!(governance.may_weaken_permanently);
            }
            // Entering disabled always starts or keeps a time box.
            if m.stored() == Mode::Disabled && previous != before.stored() {
                prop_assert!(m.time_box().is_some());
            }
        }
    }
}
