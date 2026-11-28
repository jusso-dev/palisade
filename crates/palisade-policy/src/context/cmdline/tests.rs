//! Command-line splitting (#329).

use proptest::prelude::*;

use super::*;

fn split(s: &str) -> Vec<String> {
    split_args(s)
}

/// Joins arguments into a command line that splits back into them: the
/// program name quoted unless it holds a quote (then it has no white
/// space), each argument quoted with its quotes and the backslashes before
/// them escaped.
fn join(args: &[String]) -> String {
    let mut line = String::new();
    let Some((name, rest)) = args.split_first() else {
        return line;
    };
    if name.contains('"') {
        line.push_str(name);
    } else {
        line.push('"');
        line.push_str(name);
        line.push('"');
    }
    for arg in rest {
        line.push_str(" \"");
        let mut slashes = 0;
        for c in arg.chars() {
            match c {
                '\\' => slashes += 1,
                '"' => {
                    line.extend(std::iter::repeat_n('\\', 2 * slashes + 1));
                    slashes = 0;
                }
                _ => {
                    line.extend(std::iter::repeat_n('\\', slashes));
                    slashes = 0;
                }
            }
            if c != '\\' {
                line.push(c);
            }
        }
        line.extend(std::iter::repeat_n('\\', 2 * slashes));
        line.push('"');
    }
    line
}

#[test]
fn splits_as_command_line_to_argv_does() {
    for (line, args) in [
        ("", &[][..]),
        ("a.exe", &["a.exe"][..]),
        ("a.exe b c", &["a.exe", "b", "c"]),
        ("a.exe  b\t\tc  ", &["a.exe", "b", "c"]),
        (
            r#""C:\Program Files\a.exe" -x"#,
            &[r"C:\Program Files\a.exe", "-x"],
        ),
        (r#""C:\a b\x.exe"y z"#, &[r"C:\a b\x.exe", "y", "z"]),
        (r#"a.exe "b c" d"#, &["a.exe", "b c", "d"]),
        (r#"a.exe "a""b""#, &["a.exe", r#"a"b"#]),
        (r#"a.exe a\\\"b"#, &["a.exe", r#"a\"b"#]),
        (r#"a.exe a\\"b c" d"#, &["a.exe", r"a\b c", "d"]),
        (r"a.exe C:\dir\ x", &["a.exe", r"C:\dir\", "x"]),
        (r#"a.exe "C:\dir\\" x"#, &["a.exe", r"C:\dir\", "x"]),
        (r#"a.exe "unterminated arg"#, &["a.exe", "unterminated arg"]),
        (r#"a.exe """#, &["a.exe", ""]),
        (" a.exe", &["", "a.exe"]),
        (r#"C:\a\b.exe "#, &[r"C:\a\b.exe"]),
        (r#""unterminated name"#, &["unterminated name"]),
    ] {
        assert_eq!(split(line), args, "{line:?}");
    }
}

/// Wine's `CommandLineToArgvW` table (dlls/shell32/tests/shlexec.c), which
/// Wine runs against Windows itself. The strings are copied as written in
/// C, whose escapes here mean the same as Rust's.
#[test]
fn splits_as_windows_does_in_wines_table() {
    for (line, args) in [
        ("exe", &["exe"][..]),
        (
            "exe arg1 arg2 \"arg three\" 'four five` six\\ $even)",
            &[
                "exe",
                "arg1",
                "arg2",
                "arg three",
                "'four",
                "five`",
                "six\\",
                "$even)",
            ],
        ),
        (
            "exe arg=1 arg-2 three\tfour\rfour\nfour ",
            &["exe", "arg=1", "arg-2", "three", "four\rfour\nfour"],
        ),
        (
            "exe arg\"one\" \"second\"arg thirdarg ",
            &["exe", "argone", "secondarg", "thirdarg"],
        ),
        ("exe arg1 \"unclosed", &["exe", "arg1", "unclosed"]),
        ("exe arg1 \"", &["exe", "arg1", ""]),
        (
            "exe \"one^\" \"arg\"&two three|four",
            &["exe", "one^", "arg&two", "three|four"],
        ),
        ("exe %TMPDIR% %2", &["exe", "%TMPDIR%", "%2"]),
        (
            "exe o\\ne t\\\\wo t\\\\\\ree f\\\\\\\\our ",
            &["exe", "o\\ne", "t\\\\wo", "t\\\\\\ree", "f\\\\\\\\our"],
        ),
        (
            "exe \"o\\ne\" \"t\\\\wo\" \"t\\\\\\ree\" \"f\\\\\\\\our\" ",
            &["exe", "o\\ne", "t\\\\wo", "t\\\\\\ree", "f\\\\\\\\our"],
        ),
        (
            "exe \\\"one \\\\\"two\" \\\\\\\"three \\\\\\\\\"four\" end",
            &["exe", "\"one", "\\two", "\\\"three", "\\\\four", "end"],
        ),
        (
            "exe \"one\\\" still\" \"two\\\\\" \"three\\\\\\\" still\" \"four\\\\\\\\\" end",
            &[
                "exe",
                "one\" still",
                "two\\",
                "three\\\" still",
                "four\\\\",
                "end",
            ],
        ),
        ("exe two\"\"quotes next", &["exe", "twoquotes", "next"]),
        (
            "exe three\"\"\"quotes next",
            &["exe", "three\"quotes", "next"],
        ),
        (
            "exe four\"\"\"\" quotes\" next 4%3=1",
            &["exe", "four\" quotes", "next", "4%3=1"],
        ),
        (
            "exe five\"\"\"\"\"quotes next",
            &["exe", "five\"quotes", "next"],
        ),
        (
            "exe six\"\"\"\"\"\"quotes next",
            &["exe", "six\"\"quotes", "next"],
        ),
        (
            "exe seven\"\"\"\"\"\"\" quotes\" next 7%3=1",
            &["exe", "seven\"\" quotes", "next", "7%3=1"],
        ),
        (
            "exe twelve\"\"\"\"\"\"\"\"\"\"\"\"quotes next",
            &["exe", "twelve\"\"\"\"quotes", "next"],
        ),
        (
            "exe thirteen\"\"\"\"\"\"\"\"\"\"\"\"\" quotes\" next 13%3=1",
            &["exe", "thirteen\"\"\"\" quotes", "next", "13%3=1"],
        ),
        ("exe \"two\"\"quotes next", &["exe", "two\"quotes", "next"]),
        ("exe \"two\"\" next", &["exe", "two\"", "next"]),
        (
            "exe \"three\"\"\" quotes\" next 4%3=1",
            &["exe", "three\" quotes", "next", "4%3=1"],
        ),
        (
            "exe \"four\"\"\"\"quotes next",
            &["exe", "four\"quotes", "next"],
        ),
        (
            "exe \"five\"\"\"\"\"quotes next",
            &["exe", "five\"\"quotes", "next"],
        ),
        (
            "exe \"six\"\"\"\"\"\" quotes\" next 7%3=1",
            &["exe", "six\"\" quotes", "next", "7%3=1"],
        ),
        (
            "exe \"eleven\"\"\"\"\"\"\"\"\"\"\"quotes next",
            &["exe", "eleven\"\"\"\"quotes", "next"],
        ),
        (
            "exe \"twelve\"\"\"\"\"\"\"\"\"\"\"\" quotes\" next 13%3=1",
            &["exe", "twelve\"\"\"\" quotes", "next", "13%3=1"],
        ),
        (
            "exe \"the crazy \\\\\"\"\"\\\\\" quotes",
            &["exe", "the crazy \\\"\\", "quotes"],
        ),
        ("exe\"file\"path arg1", &["exe\"file\"path", "arg1"]),
        ("exe\"file\"path\targ1", &["exe\"file\"path", "arg1"]),
        ("exe\"path\\ arg1", &["exe\"path\\", "arg1"]),
        ("\\\"exe \"arg one\"", &["\\\"exe", "arg one"]),
        ("\"spaced exe\" \"next arg\"", &["spaced exe", "next arg"]),
        ("\"spaced exe\"\t\"next arg\"", &["spaced exe", "next arg"]),
        ("\"exe\"arg\" one\" argtwo", &["exe", "arg one", "argtwo"]),
        (
            "\"spaced exe\\\"arg1 arg2",
            &["spaced exe\\", "arg1", "arg2"],
        ),
        ("\"two\"\" arg1 ", &["two", " arg1 "]),
        ("\"three\"\"\" arg2", &["three", "", "arg2"]),
        ("\"four\"\"\"\"arg1", &["four", "\"arg1"]),
        (" \"arg\"one argtwo", &["", "argone", "argtwo"]),
    ] {
        assert_eq!(split(line), args, "{line:?}");
    }
}

/// Command lines that would hide an argument from a `process.argv` deny if
/// they were split differently from Windows.
#[test]
fn no_argument_hides_from_a_criterion() {
    for (line, args) in [
        // The program name ends at its closing quote.
        (r#""a.exe"--blocked x"#, &["a.exe", "--blocked", "x"][..]),
        (r#""C:\x y\a.exe"-s"#, &[r"C:\x y\a.exe", "-s"]),
        // Quotes inside an unquoted program name are literal, and so are
        // backslashes.
        (r#"a"b"c.exe -s"#, &[r#"a"b"c.exe"#, "-s"]),
        (r#"C:\dir\"a.exe -s"#, &[r#"C:\dir\"a.exe"#, "-s"]),
        // `""` inside quotes gives `"` and closes the quotes.
        (r#"a.exe "x"" --blocked"#, &["a.exe", r#"x""#, "--blocked"]),
        (r#"test.exe "0 1"" 2"#, &["test.exe", r#"0 1""#, "2"]),
        // `"""` inside quotes gives `"` and stays open.
        (r#"test.exe "0 1""" 2"#, &["test.exe", r#"0 1" 2"#]),
        // Backslashes before a run of quotes.
        (r#"a.exe \\"" b"#, &["a.exe", r"\", "b"]),
        (r#"a.exe \\\""" b"#, &["a.exe", r#"\""#, "b"]),
        (r#"a.exe "x\\" y"#, &["a.exe", r"x\", "y"]),
        // Empty quotes are an empty argument.
        (r#"a.exe "" b"#, &["a.exe", "", "b"]),
        (r#""" b"#, &["", "b"]),
        // Trailing white space gives no argument.
        ("a.exe b \t ", &["a.exe", "b"]),
        ("\"a.exe\" \t", &["a.exe"]),
    ] {
        assert_eq!(split(line), args, "{line:?}");
    }
}

#[test]
fn arguments_are_counted_from_either_end() {
    let args = split("a.exe -r -t 30");
    assert_eq!(arg_at(&args, 0), Some("a.exe"));
    assert_eq!(arg_at(&args, 1), Some("-r"));
    assert_eq!(arg_at(&args, 3), Some("30"));
    assert_eq!(arg_at(&args, 4), None);
    assert_eq!(arg_at(&args, -1), Some("30"));
    assert_eq!(arg_at(&args, -4), Some("a.exe"));
    assert_eq!(arg_at(&args, -5), None);
    assert_eq!(arg_at(&[], -1), None);
    assert_eq!(arg_at(&args, i16::MIN), None);
}

proptest! {
    /// Splitting never panics, and gives at most one argument per byte,
    /// plus one.
    #[test]
    fn splitting_is_bounded(line in ".{0,200}") {
        let args = split(&line);
        prop_assert!(args.len() <= line.len() + 1);
    }

    /// Any split survives a join and a second split: there is one reading
    /// of the arguments.
    #[test]
    fn splitting_is_stable(line in r#"[ab "\\\t]{0,40}"#) {
        let args = split(&line);
        prop_assert_eq!(split(&join(&args)), args);
    }

    /// Simple arguments survive a join and a split.
    #[test]
    fn simple_arguments_round_trip(args in prop::collection::vec("[A-Za-z0-9._:/=-]{1,12}", 1..8)) {
        prop_assert_eq!(split(&args.join(" ")), args);
    }
}
