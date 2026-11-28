//! Reusable text buffers for the decision path (#42).
//!
//! Folding a fact for comparison ([`super::fold`]) needs somewhere to put
//! the folded text. Allocating a new `String` each time costs an allocation
//! per criterion per decision. Instead each thread keeps a small pool of
//! buffers: [`with_folded`] takes one, fills it, lends it to the caller and
//! puts it back. Buffers keep their capacity, so after the first decisions
//! on a thread the decision path does not allocate. Nested use takes
//! another buffer, so callers can fold inside a closure that already holds
//! one.

use std::cell::RefCell;

use unicode_normalization::UnicodeNormalization;

/// The most buffers a thread keeps. Deeper nesting still works; the extra
/// buffers are dropped when returned.
const POOL: usize = 8;

/// A buffer longer than this is not kept, so one huge fact does not pin
/// memory for the thread's life.
const MAX_KEPT: usize = 64 * 1024;

thread_local! {
    static BUFFERS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

/// Runs `f` with an empty buffer from the thread's pool.
pub(crate) fn with_buffer<R>(f: impl FnOnce(&mut String) -> R) -> R {
    let mut buf = BUFFERS
        .try_with(|b| b.borrow_mut().pop())
        .ok()
        .flatten()
        .unwrap_or_default();
    buf.clear();
    let out = f(&mut buf);
    if buf.capacity() <= MAX_KEPT {
        // Ignore a thread that is being torn down.
        let _ = BUFFERS.try_with(|b| {
            let mut b = b.borrow_mut();
            if b.len() < POOL {
                b.push(buf);
            }
        });
    }
    out
}

/// Appends `s`, NFC-normalised and, unless `case_sensitive`, folded with
/// the simple upper-case mapping: the text [`super::fold`] returns.
pub(crate) fn fold_into(out: &mut String, s: &str, case_sensitive: bool) {
    if s.is_ascii() {
        // ASCII is already NFC, and its simple upper case is ASCII.
        if case_sensitive {
            out.push_str(s);
        } else {
            out.extend(s.bytes().map(|b| char::from(b.to_ascii_uppercase())));
        }
    } else if case_sensitive {
        out.extend(s.nfc());
    } else {
        out.extend(s.nfc().map(super::simple_upper));
    }
}

/// Runs `f` with `s` folded as [`super::fold`] folds it, without
/// allocating once the thread's buffers are warm.
pub(crate) fn with_folded<R>(s: &str, case_sensitive: bool, f: impl FnOnce(&str) -> R) -> R {
    with_buffer(|buf| {
        fold_into(buf, s, case_sensitive);
        f(buf)
    })
}

/// Appends `s` folded as [`super::fold_path`] folds it: with the upcase
/// table, and no NFC.
pub(crate) fn fold_path_into(out: &mut String, s: &str, case_sensitive: bool) {
    if case_sensitive {
        out.push_str(s);
    } else if s.is_ascii() {
        out.extend(s.bytes().map(|b| char::from(b.to_ascii_uppercase())));
    } else {
        out.extend(s.chars().map(palisade_core::upcase::upcase_char));
    }
}

/// Runs `f` with `s` folded as [`super::fold_path`] folds it, without
/// allocating once the thread's buffers are warm.
pub(crate) fn with_path_folded<R>(s: &str, case_sensitive: bool, f: impl FnOnce(&str) -> R) -> R {
    with_buffer(|buf| {
        fold_path_into(buf, s, case_sensitive);
        f(buf)
    })
}

/// Runs `f` with `s` NFC-normalised.
pub(crate) fn with_nfc<R>(s: &str, f: impl FnOnce(&str) -> R) -> R {
    if s.is_ascii() {
        return f(s);
    }
    with_buffer(|buf| {
        buf.extend(s.nfc());
        f(buf)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folding_matches_fold() {
        for s in [
            "",
            "abc",
            "C:\\Program Files\\x.EXE",
            "straße",
            "i\u{307}",
            "e\u{301}",
            "ıİ",
            "Ǆ",
        ] {
            for cs in [false, true] {
                assert_eq!(
                    with_folded(s, cs, str::to_owned),
                    super::super::fold(s, cs),
                    "{s:?} {cs}"
                );
            }
            let nfc: String = s.nfc().collect();
            assert_eq!(with_nfc(s, str::to_owned), nfc);
        }
    }

    #[test]
    fn path_folding_matches_fold_path() {
        for s in [
            "",
            "abc",
            "C:\\Program Files\\x.EXE",
            "\u{17f}etup.exe",
            "e\u{301}",
            "\u{1f80}",
            "\u{10428}",
        ] {
            for cs in [false, true] {
                assert_eq!(
                    with_path_folded(s, cs, str::to_owned),
                    super::super::fold_path(s, cs),
                    "{s:?} {cs}"
                );
            }
        }
    }

    #[test]
    fn nesting_takes_another_buffer() {
        let out = with_folded("a", false, |a| {
            with_folded("b", false, |b| format!("{a}{b}"))
        });
        assert_eq!(out, "AB");
    }
}
