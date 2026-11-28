//! Command-line splitting (#329).

use proptest::prelude::*;

use super::*;

fn split(s: &str) -> Vec<String> {
    split_args(s)
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
        (r#""C:\a b\x.exe"y z"#, &[r"C:\a b\x.exey", "z"]),
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

    /// Simple arguments survive a join and a split.
    #[test]
    fn simple_arguments_round_trip(args in prop::collection::vec("[A-Za-z0-9._:/=-]{1,12}", 1..8)) {
        prop_assert_eq!(split(&args.join(" ")), args);
    }
}
