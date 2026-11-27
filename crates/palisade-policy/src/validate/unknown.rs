//! Validation of the unknown-application policy (#39).

use std::collections::BTreeSet;

use super::{ErrorCode, Validator};
use crate::model::unknown::limits::{
    PROMPT_TIMEOUT_MAX, PROMPT_TIMEOUT_MIN, TEMP_APPROVAL_DAYS_MAX, TEMP_APPROVAL_DAYS_MIN,
};
use crate::model::{
    ActionKind, Level, LocationClass, Notify, ObjectType, OriginClass, PolicyDocument,
    PreexistingPolicy, RuleSetKind, UnknownPolicy,
};
use crate::unknown::{prompt_valid_for, resolve_level, restrict_valid_for};

const BASE: &str = "/policy/unknown";

impl Validator {
    pub(super) fn unknown(&mut self, doc: &PolicyDocument) {
        let u = &doc.policy.unknown;
        for (t, level) in &u.by_type {
            let path = format!("{BASE}/by_type/{t}");
            if *level == Level::Restrict && !restrict_valid_for(*t) {
                self.push(
                    ErrorCode::UnknownLevelNotValidForType,
                    &path,
                    format!("`{t}` cannot be contained; `restrict` is only for executables, scripts and installers"),
                );
            }
            if *level == Level::Prompt && !prompt_valid_for(*t) {
                self.push(
                    ErrorCode::UnknownLevelNotValidForType,
                    &path,
                    format!("`{t}` loads without a user action, so it cannot be prompted for"),
                );
            }
        }
        if u.restrict_profile.is_none() && u.levels().any(|l| l == Level::Restrict) {
            self.push(
                ErrorCode::RestrictProfileRequired,
                &format!("{BASE}/restrict_profile"),
                "the `restrict` level needs `restrict_profile`, the containment profile to run unknown objects in",
            );
        }
        self.prompt_settings(u);
        self.effect_flags(&format!("{BASE}/effects"), ActionKind::Deny, &u.effects);
        if u.allow_request && u.effects.notify_for(ActionKind::Deny) == Notify::None {
            self.push(
                ErrorCode::InvalidActionOption,
                &format!("{BASE}/allow_request"),
                "the user can only raise a request from a notification; `notify: none` hides it",
            );
        }
        for (path, level) in entries(u) {
            if level == Level::Allow {
                self.push(
                    ErrorCode::UnknownAllow,
                    &path,
                    "`allow` lets unknown objects run silently; use `detect` to at least report them",
                );
            }
        }
        if let Some(preset) = u.preset {
            self.preset(doc, u, preset);
        }
    }

    fn prompt_settings(&mut self, u: &UnknownPolicy) {
        let p = &u.prompt;
        let base = format!("{BASE}/prompt");
        if p.options.is_empty() {
            self.push(
                ErrorCode::InvalidPromptSettings,
                &format!("{base}/options"),
                "a prompt needs at least one option",
            );
        }
        let mut seen = BTreeSet::new();
        for (i, o) in p.options.iter().enumerate() {
            if !seen.insert(*o) {
                self.push(
                    ErrorCode::InvalidPromptSettings,
                    &format!("{base}/options/{i}"),
                    format!("`{}` is listed more than once", super::serde_name(o)),
                );
            }
        }
        if p.fallback == Level::Prompt {
            self.push(
                ErrorCode::InvalidPromptSettings,
                &format!("{base}/fallback"),
                "the fallback applies when no prompt can be shown, so it cannot be `prompt`",
            );
        }
        if !(PROMPT_TIMEOUT_MIN..=PROMPT_TIMEOUT_MAX).contains(&p.timeout_secs) {
            self.push(
                ErrorCode::SettingOutOfRange,
                &format!("{base}/timeout_secs"),
                format!(
                    "{} is outside {PROMPT_TIMEOUT_MIN}..={PROMPT_TIMEOUT_MAX}",
                    p.timeout_secs
                ),
            );
        }
        if !(TEMP_APPROVAL_DAYS_MIN..=TEMP_APPROVAL_DAYS_MAX).contains(&p.temp_approval_days) {
            self.push(
                ErrorCode::SettingOutOfRange,
                &format!("{base}/temp_approval_days"),
                format!(
                    "{} is outside {TEMP_APPROVAL_DAYS_MIN}..={TEMP_APPROVAL_DAYS_MAX}",
                    p.temp_approval_days
                ),
            );
        }
    }

    /// The checks of a preset-tagged policy.
    fn preset(
        &mut self,
        doc: &PolicyDocument,
        u: &UnknownPolicy,
        preset: crate::model::CompliancePreset,
    ) {
        // Silent allow in user profiles or temporary folders.
        for class in [LocationClass::UserProfile, LocationClass::Temp] {
            if let Some((t, classes, origin)) = weakest(u, class, |l| l == Level::Allow) {
                self.push(
                    ErrorCode::UnknownAllowNotPermitted,
                    BASE,
                    format!(
                        "under the `{}` preset an unknown `{t}` in {} with origin `{}` would run silently; Essential Eight requires default deny in `{}` (ISM-1870)",
                        preset.as_str(),
                        describe(&classes),
                        origin.as_str(),
                        class.as_str()
                    ),
                );
            }
        }
        // Weaker than the preset for some object.
        let reference = UnknownPolicy::preset(preset);
        if let Some((t, classes, origin, ours, theirs)) =
            cases().find_map(|(t, classes, origin)| {
                let ours = floor(u, t, &classes, origin);
                let theirs = floor(&reference, t, &classes, origin);
                (ours < theirs).then_some((t, classes, origin, ours, theirs))
            })
        {
            self.push(
                ErrorCode::ComplianceWeakened,
                BASE,
                format!(
                    "weaker than the `{}` preset: an unknown `{t}` in {} with origin `{}` gets `{ours}`, the preset gives `{theirs}`",
                    preset.as_str(),
                    describe(&classes),
                    origin.as_str()
                ),
            );
        }
        if u.preexisting_policy != PreexistingPolicy::BaselineOnly {
            self.push(
                ErrorCode::ComplianceWeakened,
                &format!("{BASE}/preexisting_policy"),
                format!(
                    "weaker than the `{}` preset, which allows files present at install only through the approved baseline",
                    preset.as_str()
                ),
            );
        }
        if preset == crate::model::CompliancePreset::E8Ml3
            && u.driver_boot_policy == crate::model::DriverBootPolicy::Audit
        {
            // Kept by the preset on purpose: blocking an unrecognised
            // boot-start driver can leave the device unable to boot (ADR
            // 0018). The exemption is reported, not silent.
            self.push(
                ErrorCode::ComplianceWeakened,
                &format!("{BASE}/driver_boot_policy"),
                "under the `e8_ml3` preset unknown drivers are blocked, except during early boot: `driver_boot_policy: audit` only reports drivers loaded before the agent has fully started; set `enforce` once the device's boot-start drivers are known",
            );
        }
        if preset == crate::model::CompliancePreset::E8Ml3 {
            let referenced: BTreeSet<_> = doc.policy.rule_sets.iter().collect();
            let has_mandatory = doc.rule_sets.iter().any(|s| {
                s.mandatory
                    && s.kind == RuleSetKind::Blocklist
                    && referenced.contains(&s.id)
                    // Validation has no clock, so only a rule that is in
                    // force at every time counts: enabled, with no
                    // activity window. One that has expired, or has not
                    // started, is no mandatory blocklist.
                    && s.rules
                        .iter()
                        .any(|r| r.enabled && r.activates_at.is_none() && r.expires_at.is_none())
            });
            if !has_mandatory {
                self.push(
                    ErrorCode::MandatoryBlocklistRequired,
                    "/policy/rule_sets",
                    "the `e8_ml3` preset requires a referenced mandatory blocklist with at least one enabled rule with no `activates_at` or `expires_at` (recommended block rules and the vulnerable driver blocklist, ISM-1544, ISM-1659)",
                );
            }
        }
    }
}

/// Every level the policy sets, with its JSON Pointer.
fn entries(u: &UnknownPolicy) -> Vec<(String, Level)> {
    let mut out = vec![(format!("{BASE}/default"), u.default)];
    out.extend(
        u.by_location
            .iter()
            .map(|(k, l)| (format!("{BASE}/by_location/{}", k.as_str()), *l)),
    );
    out.extend(
        u.by_origin
            .iter()
            .map(|(k, l)| (format!("{BASE}/by_origin/{}", k.as_str()), *l)),
    );
    out.extend(
        u.by_type
            .iter()
            .map(|(k, l)| (format!("{BASE}/by_type/{k}"), *l)),
    );
    out.push((format!("{BASE}/prompt/fallback"), u.prompt.fallback));
    out
}

/// The least an unknown object of type `t` in the location classes
/// `classes`, with the single origin `origin`, can end up with: a prompt
/// may end in its fallback.
fn floor(
    u: &UnknownPolicy,
    t: ObjectType,
    classes: &BTreeSet<LocationClass>,
    origin: OriginClass,
) -> Level {
    let fallback = match u.prompt.fallback {
        Level::Prompt => Level::Block,
        other => other,
    };
    if origin == OriginClass::Preexisting && u.preexisting_policy == PreexistingPolicy::BaselineOnly
    {
        return Level::Block;
    }
    let (level, _) = resolve_level(u, t, classes, &BTreeSet::from([origin]));
    level.floor(fallback)
}

/// Every object type, with every set of one or two location classes and
/// every single origin.
///
/// These are exactly the cases that can give an object its weakest level.
/// The level is the most restrictive entry that applies, or `default` when
/// none does. So a larger set of classes or origins only ever adds entries,
/// and the most restrictive wins, except that a set where nothing applies
/// takes `default`, which a second class with a weaker entry can undercut.
/// One more class is enough for that, and one origin is always present,
/// so the weakest level over every set that contains a class is reached
/// with that class and at most one other. Any two classes are taken to be
/// able to occur together: the agent supplies the classes, and the check
/// errs towards a warning.
fn cases() -> impl Iterator<Item = (ObjectType, BTreeSet<LocationClass>, OriginClass)> {
    ObjectType::ALL.into_iter().flat_map(|t| {
        LocationClass::ALL
            .into_iter()
            .enumerate()
            .flat_map(move |(i, a)| {
                LocationClass::ALL[i..].iter().flat_map(move |b| {
                    OriginClass::ALL
                        .into_iter()
                        .map(move |o| (t, BTreeSet::from([a, *b]), o))
                })
            })
    })
}

/// A case that contains `class` and ends up at a level `bad` accepts.
fn weakest(
    u: &UnknownPolicy,
    class: LocationClass,
    bad: impl Fn(Level) -> bool,
) -> Option<(ObjectType, BTreeSet<LocationClass>, OriginClass)> {
    cases().find(|(t, classes, o)| classes.contains(&class) && bad(floor(u, *t, classes, *o)))
}

/// `` `a` `` or `` `a` and `b` ``.
fn describe(classes: &BTreeSet<LocationClass>) -> String {
    classes
        .iter()
        .map(|c| format!("`{}`", c.as_str()))
        .collect::<Vec<_>>()
        .join(" and ")
}
