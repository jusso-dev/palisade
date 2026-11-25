//! `cargo xtask check-commit-msg <file>`: the Conventional Commit lint that
//! the opt-in `commit-msg` Git hook runs (#29).
//!
//! The subject line follows the same rule as pull request titles
//! (`.github/scripts/check-pr-title.sh`), because squash merges turn the PR
//! title into the commit on `main`:
//!
//! `<type>(<optional scope>)<optional !>: <summary>`
//!
//! - `type` is one of [`TYPES`];
//! - `scope` is lowercase letters, digits, `.`, `_` or `-`, starting with a
//!   letter or digit;
//! - the summary does not start with whitespace and has no control
//!   characters.
//!
//! Git's own messages are accepted as they are: `fixup!`, `squash!` and
//! `amend!` commits (they disappear in a rebase), and `Merge` and `Revert`
//! subjects that Git writes. Comment lines (`#`) and everything after Git's
//! scissors line are ignored, as Git ignores them. A body must be separated
//! from the subject by a blank line.

/// The allowed types, as in `check-pr-title.sh`.
pub const TYPES: &[&str] = &[
    "feat", "fix", "security", "docs", "ci", "build", "refactor", "test", "chore", "revert",
];

/// Git's scissors line: everything from it on is dropped by Git.
const SCISSORS: &str = "# ------------------------ >8 ------------------------";

/// Checks a commit message. Returns the problems, empty if it is valid.
#[must_use]
pub fn check(message: &str) -> Vec<String> {
    let lines: Vec<&str> = message
        .lines()
        .take_while(|l| *l != SCISSORS)
        .filter(|l| !l.starts_with('#'))
        .collect();
    let Some(first) = lines.iter().position(|l| !l.trim().is_empty()) else {
        return vec!["the commit message is empty".to_owned()];
    };
    let subject = lines.get(first).copied().unwrap_or_default();
    let mut problems = Vec::new();
    if !is_git_generated(subject) {
        problems.extend(check_subject(subject));
    }
    if let Some(next) = lines.get(first + 1)
        && !next.trim().is_empty()
    {
        problems.push("leave a blank line between the subject and the body".to_owned());
    }
    problems
}

fn is_git_generated(subject: &str) -> bool {
    ["fixup! ", "squash! ", "amend! ", "Merge ", "Revert \""]
        .iter()
        .any(|p| subject.starts_with(p))
}

/// The subject-line rule, shared with PR titles.
fn check_subject(subject: &str) -> Vec<String> {
    let Some((head, summary)) = subject.split_once(": ") else {
        return vec![format!(
            "the subject must look like `<type>(<scope>): <summary>`, for example \
             `feat(policy): add publisher rules`; got `{subject}`"
        )];
    };
    let mut problems = Vec::new();
    let head = head.strip_suffix('!').unwrap_or(head);
    let (kind, scope) = match head.split_once('(') {
        Some((kind, rest)) => match rest.strip_suffix(')') {
            Some(scope) => (kind, Some(scope)),
            None => {
                problems.push(format!("unclosed scope in `{head}`"));
                (kind, None)
            }
        },
        None => (head, None),
    };
    if !TYPES.contains(&kind) {
        problems.push(format!(
            "unknown type `{kind}`; use one of: {}",
            TYPES.join(", ")
        ));
    }
    if let Some(scope) = scope {
        let mut chars = scope.chars();
        let first_ok = chars
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
        let rest_ok = chars
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'));
        if !first_ok || !rest_ok {
            problems.push(format!(
                "the scope `{scope}` must be lowercase letters, digits, `.`, `_` or `-`"
            ));
        }
    }
    if summary.is_empty() || summary.starts_with(char::is_whitespace) {
        problems.push("the summary after `: ` must not be empty or start with a space".to_owned());
    }
    if summary.chars().any(char::is_control) {
        problems.push("the summary must not contain control characters".to_owned());
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_messages() {
        for message in [
            "feat(policy): add publisher rule condition",
            "fix(agent): handle renamed files\n",
            "docs: explain rule precedence\n\nLonger body.\n",
            "feat(core)!: drop the old API",
            "chore(deps): bump x\n\nCo-Authored-By: someone <a@example.org>\n",
            "ci(x.y_z-1): scope characters",
            "# a comment first\nfeat: after a comment\n",
            "\n\nfeat: after blank lines",
            "fixup! anything at all",
            "squash! feat: whatever",
            "Merge branch 'main' into feat/x",
            "Revert \"feat: something\"\n\nThis reverts commit abc.",
            "feat: subject\n\n# Please enter the commit message\n",
            "feat: subject\n# ------------------------ >8 ------------------------\ndiff --git",
        ] {
            assert_eq!(check(message), Vec::<String>::new(), "{message:?}");
        }
    }

    #[test]
    fn invalid_messages() {
        for (message, expect) in [
            ("", "empty"),
            ("# only comments\n", "empty"),
            ("add a thing", "must look like"),
            ("feature: add a thing", "unknown type"),
            ("Feat: add a thing", "unknown type"),
            ("feat(Policy): add", "scope"),
            ("feat(-x): add", "scope"),
            ("feat(): add", "scope"),
            ("feat(policy: add", "unclosed"),
            ("feat:  two spaces", "must not be empty"),
            ("feat:no space", "must look like"),
            ("feat: tab\there", "control"),
            ("feat: subject\nbody without a blank line", "blank line"),
            ("wip", "must look like"),
        ] {
            let problems = check(message);
            assert!(
                problems.iter().any(|p| p.contains(expect)),
                "{message:?}: expected {expect:?}, got {problems:?}"
            );
        }
    }

    /// The PR title checker and this lint accept the same subjects: every
    /// type here is in the shell script's list, and the script's examples
    /// pass.
    #[test]
    fn types_match_the_pr_title_check() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../.github/scripts/check-pr-title.sh");
        let script = std::fs::read_to_string(path).unwrap();
        let line = script
            .lines()
            .find_map(|l| l.strip_prefix("types='"))
            .and_then(|l| l.strip_suffix('\''))
            .unwrap();
        let script_types: Vec<&str> = line.split('|').collect();
        assert_eq!(script_types, TYPES);
        for example in [
            "feat(policy): add publisher rule condition",
            "fix(agent): handle renamed files",
            "docs: explain rule precedence",
        ] {
            assert!(script.contains(example), "{example}");
            assert!(check(example).is_empty(), "{example}");
        }
    }
}
