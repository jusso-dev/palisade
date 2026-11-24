//! `cargo xtask test-summary <junit.xml>`: turns the JUnit report from
//! `cargo nextest run --profile ci` into a Markdown summary and one GitHub
//! annotation per failed test.
//!
//! This is not a general XML parser. It reads the shape nextest writes: one
//! `<testsuites>` element with counts, and `<testcase>` elements that are
//! either self-closing (passed) or contain `<failure>`, `<error>` or
//! `<skipped>`.

/// Counts and failed tests from one report.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub tests: u64,
    pub failures: u64,
    pub errors: u64,
    pub skipped: u64,
    pub time: String,
    /// `classname name` of every failed test, in report order.
    pub failed: Vec<String>,
}

/// Parses a nextest JUnit report.
pub fn parse(xml: &str) -> Result<Report, String> {
    let suites =
        tag_attributes(xml, "testsuites").ok_or("not a JUnit report: no <testsuites> element")?;
    let count = |key: &str| -> Result<u64, String> {
        attribute(suites, key).map_or(Ok(0), |v| {
            v.parse()
                .map_err(|_| format!("<testsuites {key}=\"{v}\"> is not a number"))
        })
    };
    let mut report = Report {
        tests: count("tests")?,
        failures: count("failures")?,
        errors: count("errors")?,
        skipped: count("skipped")?,
        time: attribute(suites, "time").unwrap_or_default(),
        failed: Vec::new(),
    };
    let mut rest = xml;
    while let Some(start) = rest.find("<testcase") {
        rest = rest.get(start + "<testcase".len()..).unwrap_or_default();
        let Some(tag_end) = rest.find('>') else {
            return Err("unterminated <testcase> element".to_owned());
        };
        let tag = rest.get(..tag_end).unwrap_or_default();
        let body = if tag.ends_with('/') {
            ""
        } else {
            let after = rest.get(tag_end..).unwrap_or_default();
            after
                .find("</testcase>")
                .map_or(after, |end| after.get(..end).unwrap_or_default())
        };
        if body.contains("<failure") || body.contains("<error") {
            let name = attribute(tag, "name").unwrap_or_default();
            let class = attribute(tag, "classname").unwrap_or_default();
            report.failed.push(format!("{class} {name}"));
        }
    }
    Ok(report)
}

/// The Markdown summary for the job page. `label` names the job, for
/// example `windows-latest`.
pub fn markdown(label: &str, report: &Report) -> String {
    let failed = report.failures + report.errors;
    let passed = report
        .tests
        .saturating_sub(failed)
        .saturating_sub(report.skipped);
    let mut out = format!(
        "### Tests: {label}\n\n| Tests | Passed | Failed | Skipped | Time (s) |\n|---|---|---|---|---|\n| {} | {passed} | {failed} | {} | {} |\n",
        report.tests, report.skipped, report.time
    );
    if !report.failed.is_empty() {
        out.push_str("\nFailed tests:\n\n");
        for test in &report.failed {
            out.push_str(&format!("- `{}`\n", test.replace('`', "'")));
        }
    }
    out
}

/// One `::error` workflow command per failed test.
pub fn annotations(report: &Report) -> Vec<String> {
    report
        .failed
        .iter()
        .map(|test| {
            format!(
                "::error title={}::{}",
                escape_property("Test failed"),
                escape_data(test)
            )
        })
        .collect()
}

/// Escaping for the message part of a workflow command.
fn escape_data(s: &str) -> String {
    s.replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

/// Escaping for a property value of a workflow command.
fn escape_property(s: &str) -> String {
    escape_data(s).replace(':', "%3A").replace(',', "%2C")
}

/// The attribute text of the first `<name ...>` start tag.
fn tag_attributes<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}");
    let mut rest = xml;
    loop {
        let start = rest.find(&open)?;
        rest = rest.get(start + open.len()..)?;
        // `<testsuites` must not match `<testsuitesx`.
        if rest.starts_with(|c: char| c.is_whitespace() || c == '>' || c == '/') {
            return rest.get(..rest.find('>')?);
        }
    }
}

/// The unescaped value of `key="..."` in a tag's attribute text.
fn attribute(attributes: &str, key: &str) -> Option<String> {
    let mut rest = attributes;
    loop {
        let at = rest.find(key)?;
        let before = rest.get(..at)?;
        let after = rest.get(at + key.len()..)?;
        let boundary = before.is_empty() || before.ends_with(char::is_whitespace);
        if boundary {
            if let Some(value) = after.strip_prefix("=\"") {
                return Some(unescape(value.get(..value.find('"')?)?));
            }
        }
        rest = after;
    }
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSING: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="nextest-run" tests="3" skipped="1" failures="0" errors="0" time="0.072">
    <testsuite name="palisade-core" tests="3" skipped="1" errors="0" failures="0">
        <testcase name="tests::a" classname="palisade-core" time="0.020"/>
        <testcase name="tests::b" classname="palisade-core" time="0.020"/>
        <testcase name="tests::c" classname="palisade-core" time="0.000">
            <skipped/>
        </testcase>
    </testsuite>
</testsuites>
"#;

    const FAILING: &str = r#"<testsuites name="nextest-run" tests="4" skipped="0" failures="1" errors="1" time="1.5">
    <testsuite name="xtask" tests="4" skipped="0" errors="1" failures="1">
        <testcase name="ok_one" classname="xtask" time="0.1"/>
        <testcase name="parse::&lt;T&gt;_fails" classname="xtask" time="0.1">
            <failure type="test failure">assertion failed</failure>
            <system-out>&lt;testcase name="fake"&gt;</system-out>
        </testcase>
        <testcase name="crashes" classname="xtask" time="0.1">
            <error type="test abort"/>
        </testcase>
        <testcase name="ok_two" classname="xtask" time="0.1"></testcase>
    </testsuite>
</testsuites>
"#;

    #[test]
    fn passing_report_is_summarised() {
        let report = parse(PASSING).unwrap();
        assert_eq!(
            report,
            Report {
                tests: 3,
                failures: 0,
                errors: 0,
                skipped: 1,
                time: "0.072".to_owned(),
                failed: Vec::new(),
            }
        );
        assert_eq!(
            markdown("ubuntu-latest", &report),
            "### Tests: ubuntu-latest\n\n| Tests | Passed | Failed | Skipped | Time (s) |\n|---|---|---|---|---|\n| 3 | 2 | 0 | 1 | 0.072 |\n"
        );
        assert!(annotations(&report).is_empty());
    }

    #[test]
    fn failures_and_errors_are_listed_and_annotated() {
        let report = parse(FAILING).unwrap();
        assert_eq!(report.failed, ["xtask parse::<T>_fails", "xtask crashes"]);
        let md = markdown("windows-11-arm", &report);
        assert!(md.contains("| 4 | 2 | 2 | 0 | 1.5 |"), "{md}");
        assert!(md.contains("- `xtask crashes`"), "{md}");
        assert_eq!(
            annotations(&report),
            [
                "::error title=Test failed::xtask parse::<T>_fails",
                "::error title=Test failed::xtask crashes",
            ]
        );
    }

    #[test]
    fn annotation_text_cannot_start_a_new_workflow_command() {
        let report = Report {
            failed: vec!["x\n::add-mask::y 100%".to_owned()],
            ..Report::default()
        };
        assert_eq!(
            annotations(&report),
            ["::error title=Test failed::x%0A::add-mask::y 100%25"]
        );
    }

    #[test]
    fn attribute_lookup_matches_whole_names() {
        let attrs = r#" name="n" classname="c" tests="2""#;
        assert_eq!(attribute(attrs, "name").as_deref(), Some("n"));
        assert_eq!(attribute(attrs, "classname").as_deref(), Some("c"));
        assert_eq!(attribute(attrs, "time"), None);
    }

    #[test]
    fn malformed_reports_are_errors() {
        assert!(parse("").is_err());
        assert!(parse("<testsuite tests=\"1\">").is_err());
        assert!(parse(r#"<testsuites tests="many">"#).is_err());
        assert!(parse(r#"<testsuites tests="1"><testcase name="x""#).is_err());
    }
}
