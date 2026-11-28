//! Splitting a Windows command line into arguments (#33, #329).
//!
//! `process.argv` criteria test the arguments of the process being decided.
//! The agent supplies the raw command line, from process creation (#8),
//! and [`split_args`] splits it as `CommandLineToArgvW` does. A program
//! that parses its own command line may split it differently: the C
//! runtime since 2008 reads `""` inside quotes as a literal quote that
//! keeps quoting open, and honours quotes anywhere in the program name.
//! Interpreter-specific parsing, such as cmd.exe's carets or PowerShell's
//! parameter abbreviations, is #99 and #7.
//!
//! The rules, as Wine's tests record them against Windows:
//!
//! - The first argument, the program name, ends at the first space or tab,
//!   unless it starts with `"`; then it ends at the next `"`, even with no
//!   white space after it, and what follows starts the next argument.
//!   Backslashes and other quotes in it are literal.
//! - After it, spaces and tabs outside quotes separate arguments.
//! - `2n` backslashes followed by `"` give `n` backslashes, and the `"` is
//!   a quote; `2n + 1` backslashes followed by `"` give `n` backslashes and
//!   a literal `"`. Backslashes not followed by `"` are literal.
//! - A run of quotes is counted, with the quote that opened a quoted part
//!   if inside one: each third quote gives a literal `"`, and quoting is
//!   open after the run only if the count leaves one over. So outside
//!   quotes `"` opens, `""` gives nothing and `"""` gives `"`; inside,
//!   `"` closes, `""` gives `"` and closes, and `"""` gives `"` and stays
//!   open.
//!
//! The command line is untrusted input; splitting is linear in its length,
//! never panics, and gives at most one argument per byte, plus one.

/// The largest `arg_index` a policy may use, either way: positions -255
/// to 255.
pub const MAX_ARG_INDEX: i16 = 255;

/// The arguments of a command line, the program name first.
#[must_use]
pub fn split_args(command_line: &str) -> Vec<String> {
    let mut args = Vec::new();
    if command_line.is_empty() {
        return args;
    }
    let mut chars = command_line.chars().peekable();
    // The program name: no backslash or quote-run processing.
    let mut name = String::new();
    if chars.peek() == Some(&'"') {
        chars.next();
        // It ends at the closing quote, whatever follows it: in
        // `"a.exe"--x`, `--x` is the first argument.
        for c in chars.by_ref() {
            if c == '"' {
                break;
            }
            name.push(c);
        }
    } else {
        while let Some(&c) = chars.peek() {
            if is_space(c) {
                break;
            }
            name.push(c);
            chars.next();
        }
    }
    args.push(name);

    loop {
        while chars.peek().copied().is_some_and(is_space) {
            chars.next();
        }
        if chars.peek().is_none() {
            break;
        }
        let mut arg = String::new();
        let mut quoted = false;
        while let Some(&c) = chars.peek() {
            match c {
                '\\' => {
                    let mut slashes = 0usize;
                    while chars.peek() == Some(&'\\') {
                        slashes += 1;
                        chars.next();
                    }
                    if chars.peek() == Some(&'"') {
                        arg.extend(std::iter::repeat_n('\\', slashes / 2));
                        if slashes % 2 == 1 {
                            arg.push('"');
                            chars.next();
                        }
                        // An even count leaves the `"` to the quote rule.
                    } else {
                        arg.extend(std::iter::repeat_n('\\', slashes));
                    }
                }
                '"' => {
                    // A run of quotes, counted with the opening quote if
                    // inside one: every third gives a literal `"`, and the
                    // run leaves quoting open only if one is left over.
                    let mut count = u8::from(quoted);
                    while chars.peek() == Some(&'"') {
                        chars.next();
                        count += 1;
                        if count == 3 {
                            arg.push('"');
                            count = 0;
                        }
                    }
                    quoted = count == 1;
                }
                c if is_space(c) && !quoted => break,
                c => {
                    arg.push(c);
                    chars.next();
                }
            }
        }
        args.push(arg);
    }
    args
}

const fn is_space(c: char) -> bool {
    c == ' ' || c == '\t'
}

/// The argument at `index`: from the start (0 is the program name), or from
/// the end when negative (-1 is the last). `None` if there is no such
/// argument.
#[must_use]
pub fn arg_at(args: &[String], index: i16) -> Option<&str> {
    let i = if index < 0 {
        args.len().checked_sub(usize::from(index.unsigned_abs()))?
    } else {
        usize::from(index.unsigned_abs())
    };
    args.get(i).map(String::as_str)
}

#[cfg(test)]
mod tests;
