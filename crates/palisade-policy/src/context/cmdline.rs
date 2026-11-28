//! Splitting a Windows command line into arguments (#33, #329).
//!
//! `process.argv` criteria test the arguments of the process being decided.
//! The agent supplies the raw command line, from process creation (#8),
//! and [`split_args`] splits it as `CommandLineToArgvW` and the platform C
//! runtime do. Interpreter-specific parsing, such as cmd.exe's carets or
//! PowerShell's parameter abbreviations, is #99 and #7: a criterion here
//! sees the arguments a C program would see.
//!
//! The rules:
//!
//! - The first argument, the program name, ends at the first space or tab,
//!   unless it starts with `"`; then it runs to the next `"`, and
//!   backslashes in it are literal.
//! - After it, spaces and tabs outside quotes separate arguments.
//! - `"` starts or ends a quoted part; inside one, spaces and tabs are part
//!   of the argument, and `""` is a literal `"`.
//! - `2n` backslashes followed by `"` give `n` backslashes, and the `"`
//!   starts or ends a quoted part; `2n + 1` backslashes followed by `"` give
//!   `n` backslashes and a literal `"`. Backslashes not followed by `"` are
//!   literal.
//!
//! The command line is untrusted input; splitting is linear in its length,
//! never panics, and gives at most one argument per byte, plus one.

/// The arguments of a command line, the program name first.
#[must_use]
pub fn split_args(command_line: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut chars = command_line.chars().peekable();
    // The program name.
    let mut name = String::new();
    if chars.peek() == Some(&'"') {
        chars.next();
        for c in chars.by_ref() {
            if c == '"' {
                break;
            }
            name.push(c);
        }
        // Anything after the closing quote, up to white space, belongs to
        // the name too, as `CommandLineToArgvW` reads it.
        while let Some(&c) = chars.peek() {
            if is_space(c) {
                break;
            }
            name.push(c);
            chars.next();
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
    if command_line.is_empty() {
        return args;
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
                        // An even count leaves the `"` to toggle quoting.
                    } else {
                        arg.extend(std::iter::repeat_n('\\', slashes));
                    }
                }
                '"' => {
                    chars.next();
                    if quoted && chars.peek() == Some(&'"') {
                        // `""` inside quotes is a literal quote.
                        arg.push('"');
                        chars.next();
                    } else {
                        quoted = !quoted;
                    }
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
