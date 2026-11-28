//! Validation of rule actions and effect flags (#34): the validity matrix,
//! action options and effect flags.

use std::collections::BTreeSet;

use super::{ErrorCode, Validator};
use crate::facts::PathVariable;
use crate::model::action::limits::{
    MAX_REASON_PROMPT_CHARS, MAX_SCOPE_PATH_BYTES, MAX_SCOPE_PATHS,
};
use crate::model::effects::limits::{
    MAX_HELP_URL_BYTES, MAX_NOTIFICATION_TEXT_CHARS, MAX_SUPPRESS_DUPLICATES_SECS,
    NOTIFICATION_PLACEHOLDERS,
};
use crate::model::{Action, ActionKind, Effects, Notify, ObjectType, Rule, RuleSet};

impl Validator {
    /// Checks a rule's action against the validity matrix, its options, and
    /// its effect flags.
    pub(super) fn action(&mut self, base: &str, set: &RuleSet, rule: &Rule) {
        let kind = rule.action.kind();
        let path = format!("{base}/action");

        // A mandatory rule set only holds denies, which the mandatory
        // checks report; this check would repeat them.
        if !set.mandatory && !kind.valid_in_rule_set(set.kind) {
            self.push(
                ErrorCode::ActionNotValidInRuleSet,
                &format!("{path}/type"),
                format!(
                    "`{kind}` is not valid in a `{}` rule set; use a `mixed` rule set or one of the kind the action belongs to",
                    super::serde_name(&set.kind)
                ),
            );
        }

        self.object_types(base, &rule.object_types, kind, |t| {
            kind.valid_for_object_type(t)
        });

        match &rule.action {
            Action::Deny(o) => {
                if o.kill_running {
                    self.kill_running(&path, &rule.object_types);
                }
                if o.request_template.is_some() && !o.allow_request {
                    self.push(
                        ErrorCode::InvalidActionOption,
                        &format!("{path}/request_template"),
                        "`request_template` needs `allow_request: true`",
                    );
                }
                if o.allow_request && set.mandatory {
                    self.push(
                        ErrorCode::InvalidActionOption,
                        &format!("{path}/allow_request"),
                        "a mandatory deny cannot be overridden by an approval request (ADR 0004)",
                    );
                } else if o.allow_request && rule.effects.notify_for(kind) == Notify::None {
                    self.push(
                        ErrorCode::InvalidActionOption,
                        &format!("{path}/allow_request"),
                        "the user can only raise a request from a notification; `notify: none` hides it",
                    );
                }
            }
            Action::AllowElevated(e) => {
                if let Some(prompt) = &e.reason_prompt {
                    let chars = prompt.chars().count();
                    if prompt.trim().is_empty()
                        || prompt.trim() != prompt
                        || chars > MAX_REASON_PROMPT_CHARS
                        || prompt.chars().any(|c| c.is_control() || super::is_bidi_control(c))
                    {
                        self.push(
                            ErrorCode::InvalidActionOption,
                            &format!("{path}/reason_prompt"),
                            format!(
                                "a reason prompt is 1 to {MAX_REASON_PROMPT_CHARS} characters, trimmed, with no control or bidirectional formatting characters"
                            ),
                        );
                    }
                }
            }
            Action::TrustSource(t) => self.scope_paths(&format!("{path}/scope_paths"), &t.scope_paths),
            Action::Ignore {} => self.push(
                ErrorCode::ExclusionNeedsPermission,
                &path,
                "`ignore` skips the object without a decision or an event; it is only for performance exclusions, and the server only accepts it from an administrator with the `admin.exclusions` permission (#10)",
            ),
            Action::Allow {} | Action::Audit {} | Action::AllowContained(_) | Action::Defer {} => {}
        }

        self.effects(&format!("{base}/effects"), rule);
    }

    /// Reports object types that `valid` rejects. An empty list means
    /// every object type, so it is reported when any type is rejected.
    fn object_types(
        &mut self,
        base: &str,
        types: &[ObjectType],
        kind: ActionKind,
        valid: impl Fn(ObjectType) -> bool,
    ) {
        if types.is_empty() {
            if !ObjectType::ALL.into_iter().all(&valid) {
                self.push(
                    ErrorCode::ActionNotValidForObjectType,
                    &format!("{base}/object_types"),
                    format!(
                        "`{kind}` applies only to {}; list the object types the rule is for",
                        valid_types(&valid)
                    ),
                );
            }
            return;
        }
        for (i, t) in types.iter().enumerate() {
            if !valid(*t) {
                self.push(
                    ErrorCode::ActionNotValidForObjectType,
                    &format!("{base}/object_types/{i}"),
                    format!("`{kind}` cannot apply to `{t}`"),
                );
            }
        }
    }

    fn kill_running(&mut self, path: &str, types: &[ObjectType]) {
        let valid = ActionKind::kill_running_valid_for;
        let message = if types.is_empty() {
            Some("`kill_running` cannot apply to every object type: drivers and libraries are not processes; list the object types".to_owned())
        } else {
            let bad: Vec<String> = types
                .iter()
                .filter(|t| !valid(**t))
                .map(|t| format!("`{t}`"))
                .collect();
            (!bad.is_empty()).then(|| {
                format!(
                    "`kill_running` cannot apply to {}: drivers and libraries are not processes",
                    bad.join(", ")
                )
            })
        };
        if let Some(message) = message {
            self.push(
                ErrorCode::ActionNotValidForObjectType,
                &format!("{path}/kill_running"),
                message,
            );
        }
    }

    fn scope_paths(&mut self, path: &str, paths: &[String]) {
        if paths.is_empty() || paths.len() > MAX_SCOPE_PATHS {
            self.push(
                ErrorCode::InvalidActionOption,
                path,
                format!(
                    "{} scope paths; between 1 and {MAX_SCOPE_PATHS} are allowed",
                    paths.len()
                ),
            );
        }
        let mut seen = BTreeSet::new();
        for (i, p) in paths.iter().enumerate() {
            let at = format!("{path}/{i}");
            if let Some(problem) = scope_path_problem(p) {
                self.push(ErrorCode::InvalidActionOption, &at, problem);
            } else if !seen.insert(scope_path_key(p)) {
                self.push(
                    ErrorCode::InvalidActionOption,
                    &at,
                    format!(
                        "scope path `{p}` is repeated: paths compare without case or a trailing `\\`"
                    ),
                );
            }
        }
    }

    fn effects(&mut self, base: &str, rule: &Rule) {
        self.effect_flags(base, rule.action.kind(), &rule.effects);
    }

    /// Checks effect flags as those of an action of `kind`.
    pub(super) fn effect_flags(&mut self, base: &str, kind: ActionKind, e: &Effects) {
        if matches!(kind, ActionKind::Ignore | ActionKind::Defer) {
            if !e.is_empty() {
                self.push(
                    ErrorCode::EffectsNotApplicable,
                    base,
                    format!("`{kind}` makes no decision, so it has no effects; remove `effects`"),
                );
            }
            return;
        }

        if let Some(log) = e.log.filter(|l| !l.allowed_for(kind)) {
            self.push(
                ErrorCode::LogLevelNotAllowed,
                &format!("{base}/log"),
                format!(
                    "`{kind}` needs an event per decision, so `{}` is not allowed; use `always` or `sampled`",
                    super::serde_name(&log)
                ),
            );
        }

        let notify = e.notify_for(kind);
        if notify == Notify::Custom && e.notification_text.is_none() {
            self.push(
                ErrorCode::InvalidNotification,
                &format!("{base}/notify"),
                "`notify: custom` needs `notification_text`",
            );
        }
        if let Some(text) = &e.notification_text {
            let path = format!("{base}/notification_text");
            if notify != Notify::Custom {
                self.push(
                    ErrorCode::InvalidNotification,
                    &path,
                    "`notification_text` is only used with `notify: custom`",
                );
            } else if let Some(problem) = notification_text_problem(text) {
                self.push(ErrorCode::InvalidNotification, &path, problem);
            }
        }
        if let Some(url) = &e.help_url {
            let path = format!("{base}/help_url");
            if notify == Notify::None {
                self.push(
                    ErrorCode::InvalidNotification,
                    &path,
                    "`help_url` is only shown with a notification; it has no effect with `notify: none`",
                );
            } else if let Some(problem) = help_url_problem(url) {
                self.push(ErrorCode::InvalidNotification, &path, problem);
            }
        }

        self.tags(&format!("{base}/tags"), &e.tags);

        if let Some(secs) = e.suppress_duplicates_secs
            && secs > MAX_SUPPRESS_DUPLICATES_SECS
        {
            self.push(
                ErrorCode::InvalidEffect,
                &format!("{base}/suppress_duplicates_secs"),
                format!("{secs} is outside 0..={MAX_SUPPRESS_DUPLICATES_SECS}"),
            );
        }
    }
}

/// The object types `valid` accepts, for messages. Script kinds are
/// written once, as `script.*`.
fn valid_types(valid: &impl Fn(ObjectType) -> bool) -> String {
    let mut names: Vec<String> = Vec::new();
    for t in ObjectType::ALL.into_iter().filter(|t| valid(*t)) {
        let name = match t {
            ObjectType::Script(_) => "`script.*`".to_owned(),
            other => format!("`{other}`"),
        };
        if !names.contains(&name) {
            names.push(name);
        }
    }
    names.join(", ")
}

/// Why a notification text is not acceptable, if it is not.
///
/// It is 1 to 2048 characters, with no control or bidirectional formatting
/// characters other than tab and line breaks. `{name}` is a placeholder
/// and must be one of [`NOTIFICATION_PLACEHOLDERS`]; `{{` and `}}` are
/// literal braces.
pub(crate) fn notification_text_problem(text: &str) -> Option<String> {
    let chars = text.chars().count();
    if text.trim().is_empty() {
        return Some("must not be empty or only whitespace".to_owned());
    }
    if chars > MAX_NOTIFICATION_TEXT_CHARS {
        return Some(format!(
            "{chars} characters; at most {MAX_NOTIFICATION_TEXT_CHARS} are allowed"
        ));
    }
    if text
        .chars()
        .any(|c| (c.is_control() && !matches!(c, '\t' | '\n' | '\r')) || super::is_bidi_control(c))
    {
        return Some(
            "must not contain control or bidirectional formatting characters other than tab and line breaks"
                .to_owned(),
        );
    }
    let mut rest = text;
    while let Some(i) = rest.find(['{', '}']) {
        let at = &rest[i..];
        if let Some(after) = at.strip_prefix("{{").or_else(|| at.strip_prefix("}}")) {
            rest = after;
        } else if let Some(after) = at.strip_prefix('{') {
            let Some(end) = after
                .find(['{', '}'])
                .filter(|&e| after[e..].starts_with('}'))
            else {
                return Some(
                    "`{` opens a placeholder that is not closed; write `{{` for a literal brace"
                        .to_owned(),
                );
            };
            let name = &after[..end];
            if !NOTIFICATION_PLACEHOLDERS.contains(&name) {
                return Some(format!(
                    "unknown placeholder `{{{name}}}`; the placeholders are {}",
                    NOTIFICATION_PLACEHOLDERS
                        .iter()
                        .map(|p| format!("`{{{p}}}`"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            rest = &after[end + 1..];
        } else {
            return Some("`}` closes no placeholder; write `}}` for a literal brace".to_owned());
        }
    }
    None
}

/// Why a help URL is not acceptable, if it is not.
///
/// It must be an `https` URL of at most 2048 bytes, in printable ASCII with
/// none of the characters RFC 3986 never allows in a URL (`"`, `<`, `>`,
/// `\\`, `^`, `` ` ``, `{`, `|`, `}`); browsers read `\\` as `/`, so
/// `https://\\evil` would have no host. The authority is a host name
/// (labels of letters, digits and `-`, not starting or ending with `-`,
/// so an internationalised name is written in its ASCII form) or a
/// bracketed IPv6 address, then an optional port from 1 to 65535. User
/// information (`user@`) is rejected.
pub(crate) fn help_url_problem(url: &str) -> Option<&'static str> {
    if url.len() > MAX_HELP_URL_BYTES {
        return Some("at most 2048 bytes are allowed");
    }
    if !url.bytes().all(|b| b.is_ascii_graphic()) {
        return Some("must be printable ASCII with no spaces");
    }
    if url.contains(['"', '<', '>', '\\', '^', '`', '{', '|', '}']) {
        return Some("must not contain `\"`, `<`, `>`, `\\`, `^`, `` ` ``, `{`, `|` or `}`");
    }
    let Some(rest) = url.strip_prefix("https://") else {
        return Some("must be an `https://` URL");
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.contains('@') {
        return Some("must not contain user information (`user@`)");
    }
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let Some(end) = v6.find(']') else {
            return Some("an IPv6 host is written in brackets: `[2001:db8::1]`");
        };
        let address = &v6[..end];
        if address.parse::<core::net::Ipv6Addr>().is_err() {
            return Some("the bracketed host is not an IPv6 address");
        }
        match &v6[end + 1..] {
            "" => (address, None),
            p => match p.strip_prefix(':') {
                Some(port) => (address, Some(port)),
                None => return Some("only a `:port` may follow the host"),
            },
        }
    } else {
        match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    if host.is_empty() {
        return Some("must name a host");
    }
    if !authority.starts_with('[') {
        let label_ok = |l: &str| {
            (1..=63).contains(&l.len())
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        };
        // One trailing dot (a fully qualified name) is allowed.
        let name = host.strip_suffix('.').unwrap_or(host);
        if host.len() > 253 || !name.split('.').all(label_ok) {
            return Some(
                "the host must be a name of letters, digits, `-` and `.`, or a bracketed IPv6 address",
            );
        }
    }
    if let Some(port) = port {
        let valid = !port.is_empty()
            && port.len() <= 5
            && port.bytes().all(|b| b.is_ascii_digit())
            && port.parse::<u32>().is_ok_and(|p| (1..=65_535).contains(&p));
        if !valid {
            return Some("the port must be a number from 1 to 65535");
        }
    }
    None
}

/// Why a trust-source scope path is not acceptable, if it is not.
///
/// A scope path is an absolute folder: a drive path (`C:\...`), a UNC path
/// (`\\server\share...`), or a known path variable ([`PathVariable`], such
/// as `%PROGRAMFILES%`) at the start, alone or followed by `\`. It is
/// written with `\`, at most 1024 bytes. Rejected: wildcards; `%` anywhere
/// else (a variable is only expanded at the start, as in criteria);
/// characters Windows does not allow in names (`<`, `>`, `"`, `|`); `.`
/// and `..` components; components ending in `.` or a space, which
/// Windows drops; `:` after the drive (data streams); device paths
/// (`\\?\`, `\\.\`); and control or bidirectional formatting characters.
/// Matching the paths is #114.
pub(crate) fn scope_path_problem(path: &str) -> Option<String> {
    if path.is_empty() {
        return Some("must not be empty".to_owned());
    }
    if path.len() > MAX_SCOPE_PATH_BYTES {
        return Some(format!(
            "{} bytes; at most {MAX_SCOPE_PATH_BYTES} are allowed",
            path.len()
        ));
    }
    if path
        .chars()
        .any(|c| c.is_control() || super::is_bidi_control(c))
    {
        return Some("must not contain control or bidirectional formatting characters".to_owned());
    }
    if path.contains('/') {
        return Some("write the path with `\\`, not `/`".to_owned());
    }
    if path.contains(['*', '?']) {
        return Some("wildcards are not supported in scope paths".to_owned());
    }
    if path.contains(['<', '>', '"', '|']) {
        return Some("`<`, `>`, `\"` and `|` are not allowed in Windows names".to_owned());
    }
    let bytes = path.as_bytes();
    let rest: Vec<&str> = if let Some(unc) = path.strip_prefix("\\\\") {
        // UNC: `\\server\share`, then optional components. `\\?\` was
        // rejected above (`?`), and `\\.\` is caught below (`.`). The
        // server and share are components too.
        let parts: Vec<&str> = unc.split('\\').collect();
        let server = parts.first().copied().unwrap_or_default();
        let share = parts.get(1).copied().unwrap_or_default();
        if server.is_empty() || share.is_empty() {
            return Some("a UNC path needs a server and a share: `\\\\server\\share`".to_owned());
        }
        parts
    } else if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && bytes[2] == b'\\'
    {
        path[3..].split('\\').collect()
    } else if let Some(after) = path.strip_prefix('%') {
        let Some(end) = after.find('%') else {
            return Some("a path variable is written `%NAME%`".to_owned());
        };
        let name = &after[..end];
        if PathVariable::from_name(name).is_none() {
            return Some(format!(
                "`%{name}%` is not a known path variable; the variables are {}",
                variable_names()
            ));
        }
        match after[end + 1..].strip_prefix('\\') {
            Some(tail) => tail.split('\\').collect(),
            None if after.len() == end + 1 => Vec::new(),
            None => {
                return Some("a path variable is followed by `\\` or ends the path".to_owned());
            }
        }
    } else {
        return Some(
            "must be absolute: `C:\\...`, `\\\\server\\share\\...` or a path variable such as `%PROGRAMFILES%\\...`"
                .to_owned(),
        );
    };
    // A trailing `\` leaves one empty last component; any other empty
    // component is a doubled `\`.
    let last = rest.len().saturating_sub(1);
    for (i, component) in rest.iter().enumerate() {
        if component.is_empty() && i != last {
            return Some("must not contain an empty component (`\\\\`)".to_owned());
        }
        if matches!(*component, "." | "..") {
            return Some("must not contain `.` or `..` components".to_owned());
        }
        // Windows drops trailing dots and spaces from a name, so `Apps.`
        // would name `Apps`; and `:` after the drive names a data stream.
        // Either would make the path mean something other than it reads.
        if component.ends_with(['.', ' ']) {
            return Some("a component must not end with `.` or a space".to_owned());
        }
        if component.contains(':') {
            return Some("`:` is only allowed after the drive letter".to_owned());
        }
        if component.contains('%') {
            return Some(
                "`%` is only allowed in a path variable at the start of the path".to_owned(),
            );
        }
    }
    None
}

/// The key two scope paths are compared by: without a trailing `\` (except
/// on a drive root), with a leading variable written by its canonical name
/// (`%TMP%` is `%TEMP%`), and folded as the engine folds paths (NFC, then
/// simple upper case, [`crate::ops::fold`]). Only for paths
/// [`scope_path_problem`] accepts.
pub(crate) fn scope_path_key(path: &str) -> String {
    let trimmed = match path.strip_suffix('\\') {
        Some(t) if !(t.len() == 2 && t.ends_with(':')) => t,
        _ => path,
    };
    let canonical = trimmed
        .strip_prefix('%')
        .and_then(|after| {
            let end = after.find('%')?;
            let variable = PathVariable::from_name(&after[..end])?;
            Some(format!(
                "%{}%{}",
                variable_name(variable),
                &after[end + 1..]
            ))
        })
        .unwrap_or_else(|| trimmed.to_owned());
    crate::ops::fold(&canonical, false)
}

/// The canonical name of a path variable, without the `%` signs.
const fn variable_name(v: PathVariable) -> &'static str {
    match v {
        PathVariable::Windir => "WINDIR",
        PathVariable::System32 => "SYSTEM32",
        PathVariable::ProgramFiles => "PROGRAMFILES",
        PathVariable::ProgramData => "PROGRAMDATA",
        PathVariable::OsDrive => "OSDRIVE",
        PathVariable::UserProfile => "USERPROFILE",
        PathVariable::AppData => "APPDATA",
        PathVariable::LocalAppData => "LOCALAPPDATA",
        PathVariable::Temp => "TEMP",
        PathVariable::Public => "PUBLIC",
        PathVariable::Removable => "REMOVABLE",
        PathVariable::Hot => "HOT",
    }
}

fn variable_names() -> String {
    PathVariable::ALL
        .iter()
        .map(|v| format!("`%{}%`", variable_name(*v)))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests;
