//! Command-line capture (#59, ISM-1889).
//!
//! Policy decides whether command lines are captured (`capture_cmdline`,
//! on by default). A captured command line is redacted first, with the same
//! linear-time engine as decision traces
//! ([`palisade_policy::trace::privacy::Redactor`]), and then cut to
//! [`MAX_CMDLINE_CHARS`]. Redacting before cutting means a secret that
//! straddles the cut is removed whole, never left half-visible.
//!
//! The default patterns remove common secret-bearing arguments: a value
//! after `password=`, `pwd:`, `token=` and the like, and the argument after
//! `-p`, `/p` or `--password`. Policy may add patterns; the defaults always
//! apply, so a policy can make redaction stricter but not weaker.

#![forbid(unsafe_code)]

use palisade_policy::trace::privacy::{RedactionError, Redactor};

use super::tree::CommandLine;

/// The longest command line kept, in characters: the event schema's long
/// text limit.
pub const MAX_CMDLINE_CHARS: usize = 32_767;

/// The redaction patterns that always apply.
pub const DEFAULT_PATTERNS: &[&str] = &[
    // `password=x`, `pwd: x`, `token=x`, `secret=x`, `apikey=x`, ...
    r#"(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)\s*[=:]\s*(?:"[^"]*"|'[^']*'|\S+)"#,
    // `-p x`, `/p x`, `--password x`, `-password x`, `/password:x`
    r#"(?:^|\s)(?:-p|/p|--?password|/password)(?:\s+|:)(?:"[^"]*"|'[^']*'|\S+)"#,
];

/// How command lines are captured.
#[derive(Clone, Debug)]
pub struct CmdlinePolicy {
    capture: bool,
    redactor: Redactor,
}

impl CmdlinePolicy {
    /// Capture on, with the default patterns and `extra` ones.
    ///
    /// # Errors
    ///
    /// The first extra pattern that does not compile.
    pub fn new<S: AsRef<str>>(capture: bool, extra: &[S]) -> Result<Self, RedactionError> {
        let mut patterns: Vec<&str> = DEFAULT_PATTERNS.to_vec();
        patterns.extend(extra.iter().map(AsRef::as_ref));
        let redactor = Redactor::new(&patterns).map_err(|mut e| {
            e.index = e.index.saturating_sub(DEFAULT_PATTERNS.len());
            e
        })?;
        Ok(Self { capture, redactor })
    }

    /// The command line to record for `raw`.
    #[must_use]
    pub fn apply(&self, raw: Option<&str>) -> CommandLine {
        if !self.capture {
            return CommandLine::Disabled;
        }
        let Some(raw) = raw else {
            return CommandLine::Unavailable;
        };
        let redacted = self.redactor.redact(raw);
        match redacted.char_indices().nth(MAX_CMDLINE_CHARS) {
            Some((cut, _)) => CommandLine::Captured {
                text: redacted[..cut].to_owned(),
                truncated: true,
            },
            None => CommandLine::Captured {
                text: redacted,
                truncated: false,
            },
        }
    }
}

impl Default for CmdlinePolicy {
    fn default() -> Self {
        Self::new::<&str>(true, &[]).unwrap_or_else(|_| Self {
            capture: false,
            redactor: Redactor::none(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(p: &CmdlinePolicy, raw: &str) -> String {
        p.apply(Some(raw)).text().unwrap().to_owned()
    }

    #[test]
    fn default_patterns_compile_and_redact() {
        let p = CmdlinePolicy::default();
        assert_eq!(
            text(&p, "app.exe password=hunter2 -v"),
            "app.exe [redacted] -v"
        );
        assert_eq!(text(&p, "app.exe PWD: \"a b\" -v"), "app.exe [redacted] -v");
        assert_eq!(text(&p, "app.exe --token='x y'"), "app.exe --[redacted]");
        assert_eq!(
            text(&p, "mysql -u root -p s3cret db"),
            "mysql -u root[redacted] db"
        );
        assert_eq!(text(&p, "net use /password:abc"), "net use[redacted]");
        assert_eq!(text(&p, "cmd.exe /c dir"), "cmd.exe /c dir");
    }

    #[test]
    fn capture_can_be_off_and_text_can_be_missing() {
        let off = CmdlinePolicy::new::<&str>(false, &[]).unwrap();
        assert_eq!(off.apply(Some("x")), CommandLine::Disabled);
        assert_eq!(
            CmdlinePolicy::default().apply(None),
            CommandLine::Unavailable
        );
    }

    #[test]
    fn extra_patterns_add_to_the_defaults() {
        let p = CmdlinePolicy::new(true, &["corp-[0-9]+"]).unwrap();
        assert_eq!(text(&p, "a corp-123 password=x"), "a [redacted] [redacted]");
        let err = CmdlinePolicy::new(true, &["ok", "("]).unwrap_err();
        assert_eq!(err.index, 1);
    }

    #[test]
    fn long_lines_are_redacted_then_cut() {
        let p = CmdlinePolicy::default();
        let raw = format!("{} password=secret", "a".repeat(MAX_CMDLINE_CHARS - 5));
        let CommandLine::Captured { text, truncated } = p.apply(Some(&raw)) else {
            panic!()
        };
        assert!(truncated);
        assert_eq!(text.chars().count(), MAX_CMDLINE_CHARS);
        assert!(!text.contains("secret"));
        assert!(!text.contains("pass"));
        let short = p.apply(Some("é".repeat(MAX_CMDLINE_CHARS).as_str()));
        assert!(matches!(
            short,
            CommandLine::Captured {
                truncated: false,
                ..
            }
        ));
    }
}
