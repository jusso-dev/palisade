//! Which bundle the agent runs, and whether a new bundle is accepted.
//!
//! [`startup`] picks what to load from the cache files and the record
//! copies, following the failure table of ADR 0018 (which supersedes ADR
//! 0012) and the startup steps of ADR 0007 (still `proposed`):
//!
//! | State | [`Load`] | Events |
//! |---|---|---|
//! | `active` passes and is at or above the floor | `Active` | none, or `policy.signature.invalid` if loaded unsigned under `audit`/`warn` |
//! | `active` fails; `previous` verifies and is the recorded fallback, or at or above the floor | `Previous` | the rejection of `active`, `policy.lkg_loaded` |
//! | both fail, after a policy was ever accepted | `Emergency` | each rejection, `policy.emergency_loaded`, and `tamper.policy.rollback_suspected` if the floor rejected a bundle |
//! | no policy was ever accepted | `FirstInstall` | none |
//!
//! Record copies that are missing, corrupt or disagree raise
//! `tamper.policy.rollback_suspected`, except for the disagreement an
//! interrupted activation leaves ([`RecordCopies::interrupted_activation`]).
//! Staleness never changes what loads ([`super::stale`]).
//!
//! [`pending`] decides whether a downloaded bundle is activated, and
//! returns the record values to write before and after the rename (ADR 0007
//! activation steps 1 to 5).
//!
//! "A policy was ever accepted" (ADR 0018) is: the floor is above zero, an
//! `active` or `previous` file exists, or a record copy exists but does not
//! unseal. The last is stricter than the ADR: a corrupt copy is evidence
//! that a record was written, so it never opens the first-install path.

use super::record::{CopyState, Record, RecordCopies};
use super::{BundleMeta, EffectiveMode, Examined, Passed, Rejection, Target, check};
use crate::events::EventType;

/// A cache file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CacheFile {
    /// The current bundle.
    Active,
    /// The bundle `active` replaced (N-1).
    Previous,
    /// A downloaded bundle not yet activated.
    Pending,
}

/// What the agent runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Load {
    /// The `active` bundle. `signed` is false only when the signature mode
    /// tolerated an invalid signature.
    Active {
        /// The bundle.
        bundle: BundleMeta,
        /// Whether its signature verified.
        signed: bool,
    },
    /// The `previous` bundle, under the one-step exception.
    Previous(BundleMeta),
    /// The built-in emergency policy, in enforce mode (#225, ADR 0018).
    Emergency,
    /// No policy was ever accepted: the built-in first-install defaults
    /// (audit mode, mandatory blocklists enforced).
    FirstInstall,
}

/// Why the anti-rollback record is suspect. Several may hold at once; they
/// are reported as one `tamper.policy.rollback_suspected` event.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Suspicion {
    /// A copy is missing although a policy was accepted.
    pub copy_missing: bool,
    /// A copy exists but does not unseal.
    pub copy_corrupt: bool,
    /// Intact copies disagree, and not as an interrupted activation would.
    pub copies_disagree: bool,
    /// A bundle on disk was below the floor and nothing else could load.
    pub floor_rejected_all: bool,
}

impl Suspicion {
    fn any(self) -> bool {
        self.copy_missing || self.copy_corrupt || self.copies_disagree || self.floor_rejected_all
    }
}

/// Something the agent reports. Each maps to exactly one event type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Finding {
    /// A cache file was not loaded.
    Rejected {
        /// Which file.
        file: CacheFile,
        /// Why.
        reason: Rejection,
    },
    /// A bundle with an invalid signature was loaded because the mode is
    /// `audit` or `warn`.
    LoadedUnsigned,
    /// `previous` was loaded because `active` failed.
    LkgLoaded,
    /// The emergency policy was loaded.
    EmergencyLoaded,
    /// The anti-rollback record is suspect.
    RollbackSuspected(Suspicion),
}

impl Finding {
    /// The event this finding raises.
    #[must_use]
    pub const fn event_type(self) -> EventType {
        match self {
            Self::Rejected { reason, .. } => reason.event_type(),
            Self::LoadedUnsigned => EventType::PolicySignatureInvalid,
            Self::LkgLoaded => EventType::PolicyLkgLoaded,
            Self::EmergencyLoaded => EventType::PolicyEmergencyLoaded,
            Self::RollbackSuspected(_) => EventType::TamperPolicyRollbackSuspected,
        }
    }
}

/// What the agent reads at startup. `None` means the file does not exist.
#[derive(Clone, Copy, Debug)]
pub struct Startup<'a> {
    /// This device's tenant and target.
    pub target: Target,
    /// Every copy of the anti-rollback record.
    pub record: &'a RecordCopies,
    /// The `active` file. Delete any leftover `pending` before startup: it
    /// was never activated.
    pub active: Option<Examined>,
    /// The `previous` file.
    pub previous: Option<Examined>,
    /// The signature mode in force.
    pub mode: EffectiveMode,
}

/// The startup decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selection {
    /// What to run.
    pub load: Load,
    /// The record every copy should hold now. Its floor is never below the
    /// highest floor read.
    pub record: Record,
    /// Whether any copy differs from [`Self::record`] and should be
    /// rewritten.
    pub rewrite_record: bool,
    /// What to report, in order.
    pub findings: Vec<Finding>,
    /// Whether to check in at once to fetch a fresh bundle.
    pub rapid_check_in: bool,
}

/// Picks what to run at startup.
#[must_use]
pub fn startup(input: &Startup<'_>) -> Selection {
    let copies = input.record;
    let floor = copies.floor();
    let fallback = copies.fallback();
    let mut findings = Vec::new();
    let mut floor_rejected = false;
    let mut reject = |findings: &mut Vec<Finding>, file, reason| {
        floor_rejected |= reason == Rejection::Rollback;
        findings.push(Finding::Rejected { file, reason });
    };

    // `active`: every check, and at or above the floor.
    let active = input.active.map(|e| {
        check(e, input.target, input.mode).and_then(|p| {
            if p.meta().version < floor {
                Err(Rejection::Rollback)
            } else {
                Ok(p)
            }
        })
    });
    let mut load = None;
    match active {
        Some(Ok(p)) => {
            if let Passed::Unsigned(_) = p {
                findings.push(Finding::LoadedUnsigned);
            }
            load = Some(Load::Active {
                bundle: p.meta(),
                signed: matches!(p, Passed::Verified(_)),
            });
        }
        Some(Err(reason)) => reject(&mut findings, CacheFile::Active, reason),
        None => {}
    }

    // `previous`: only if `active` failed, only verified, and only the
    // recorded fallback or a version the floor accepts.
    if load.is_none()
        && let Some(e) = input.previous
    {
        match check(e, input.target, EffectiveMode::ENFORCE) {
            Ok(p) => {
                let v = p.meta().version;
                if v >= floor || Some(v) == fallback {
                    load = Some(Load::Previous(p.meta()));
                    findings.push(Finding::LkgLoaded);
                } else {
                    reject(&mut findings, CacheFile::Previous, Rejection::Rollback);
                }
            }
            Err(reason) => reject(&mut findings, CacheFile::Previous, reason),
        }
    }

    let ever_accepted =
        floor > 0 || input.active.is_some() || input.previous.is_some() || copies.any_corrupt();
    let load = match load {
        Some(l) => l,
        None if ever_accepted => {
            findings.push(Finding::EmergencyLoaded);
            Load::Emergency
        }
        None => Load::FirstInstall,
    };

    let active_signed = match load {
        Load::Active {
            bundle,
            signed: true,
        } => Some(bundle.version),
        _ => None,
    };
    let suspicion = Suspicion {
        copy_missing: ever_accepted && copies.any_missing(),
        copy_corrupt: copies.any_corrupt(),
        copies_disagree: copies.disagree() && !copies.interrupted_activation(active_signed),
        floor_rejected_all: floor_rejected && load == Load::Emergency,
    };
    if suspicion.any() {
        findings.push(Finding::RollbackSuspected(suspicion));
    }

    // The record to keep: never a lower floor. A verified `active` above the
    // floor completes an interrupted activation (step 5).
    let record = match active_signed {
        Some(v) if v > floor => {
            Record::new(input.target, v, None).unwrap_or_else(|_| copies.record())
        }
        _ => copies.record(),
    };
    // On the first-install path there is nothing to protect yet: `pending`
    // writes every copy before the first `active` exists.
    let rewrite_record = load != Load::FirstInstall
        && copies
            .states()
            .iter()
            .any(|c| *c != CopyState::Intact(record));
    let rapid_check_in = matches!(load, Load::Previous(_) | Load::Emergency) || suspicion.any();
    Selection {
        load,
        record,
        rewrite_record,
        findings,
        rapid_check_in,
    }
}

impl Selection {
    /// The `active` bundle as [`pending`] needs it: `Some` only when the
    /// agent runs `active` with a verified signature. `None` while running
    /// `previous`, the emergency policy, the first-install defaults or an
    /// unsigned bundle, so a re-fetched copy of the failed version is
    /// accepted (ADR 0007, step 1).
    #[must_use]
    pub const fn loadable_active(&self) -> Option<BundleMeta> {
        match self.load {
            Load::Active {
                bundle,
                signed: true,
            } => Some(bundle),
            _ => None,
        }
    }
}

/// The plan for activating a pending bundle (ADR 0007 steps 2 to 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Activation {
    /// The bundle to activate.
    pub bundle: BundleMeta,
    /// Whether its signature verified. An unsigned bundle (tolerated by
    /// `audit` or `warn`) never raises the floor or becomes a fallback.
    pub signed: bool,
    /// Step 2: copy the current `active` to `previous` first.
    pub copy_active_to_previous: bool,
    /// Step 3: write this to every copy before the rename (the fallback
    /// cleared). Write it even on the first activation, so that every copy
    /// exists before an `active` file does.
    pub record_before_rename: Record,
    /// Step 5: write this to every copy after the rename is durable.
    pub record_after_rename: Record,
}

/// What to do with a pending bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PendingOutcome {
    /// Activate it.
    Activate(Box<Activation>),
    /// It is the current bundle: an idempotent no-op (`policy.applied`).
    AlreadyCurrent,
}

/// Decides whether a pending bundle is activated (#225 check order, ADR
/// 0007 step 1). `record` is the record in force and `active` is
/// [`Selection::loadable_active`], updated after each activation. On `Err`,
/// keep what is loaded and report the rejection's event (ADR 0018, "new
/// bundle fails verification").
///
/// # Errors
///
/// The [`Rejection`] that refused the bundle.
pub fn pending(
    examined: Examined,
    target: Target,
    record: Record,
    active: Option<BundleMeta>,
    mode: EffectiveMode,
) -> Result<PendingOutcome, Rejection> {
    let passed = check(examined, target, mode)?;
    let meta = passed.meta();
    if meta.version < record.floor() {
        return Err(Rejection::Rollback);
    }
    if let Some(a) = active {
        if meta.version < a.version {
            return Err(Rejection::Rollback);
        }
        if meta.version == a.version {
            return if meta.sha256 == a.sha256 {
                Ok(PendingOutcome::AlreadyCurrent)
            } else {
                Err(Rejection::VersionReused)
            };
        }
    }
    let signed = matches!(passed, Passed::Verified(_));
    let before = record.without_fallback();
    let after = match (signed, active) {
        (true, Some(a)) => Record::new(target, meta.version, Some(a.version)),
        (true, None) => Record::new(target, meta.version, None),
        (false, _) => Ok(before),
    }
    .unwrap_or(before);
    Ok(PendingOutcome::Activate(Box::new(Activation {
        bundle: meta,
        signed,
        copy_active_to_previous: active.is_some(),
        record_before_rename: before,
        record_after_rename: after,
    })))
}
