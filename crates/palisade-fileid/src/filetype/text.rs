//! Text, scripts, HTML applications and registry files.
//!
//! The head is decoded (byte order marks for UTF-8, UTF-16 and UTF-32, and
//! UTF-16 without one), then checked in order of certainty:
//!
//! 1. definite markers: a shebang line, a registry file header, the
//!    `<HTA:APPLICATION` element, `<?php`, script component and script file
//!    elements, and so on ([`Confidence::High`]);
//! 2. a script signature block marker near the end of the file (#52), which
//!    names its language;
//! 3. keyword counts per language ([`Confidence::Low`] or
//!    [`Confidence::Medium`]). These never override what the extension
//!    claims (see `apply_name_hints`).
//!
//! Content that does not look like text is [`FileKind::Unknown`].

#![forbid(unsafe_code)]

use std::io::{Read, Seek};

use super::name::NameInfo;
use super::source::{HEAD_LEN, Source};
use super::{
    Classification, Confidence, ExtensionKind, FileKind, ParseError, ScriptKind, TextEncoding,
};

/// How much of the end of the file is searched for a signature block
/// marker, when the file is longer than the head.
const TAIL_LEN: usize = 64 * 1024;

/// The shortest printable start, in characters, taken as a script's text
/// when binary data follows it.
const MIN_PRINTABLE_PREFIX: usize = 8;

/// Classifies text content.
pub(super) fn classify<R: Read + Seek + ?Sized>(
    src: &mut Source<'_, R>,
    name: &NameInfo,
    out: &mut Classification,
) {
    classify_within(src, name, out, HEAD_LEN);
}

/// Classifies text content from only the first `limit` bytes of the head.
/// Used for a disc image's system area that holds a script, so the volume
/// descriptors after it are not read as part of the script.
pub(super) fn classify_within<R: Read + Seek + ?Sized>(
    src: &mut Source<'_, R>,
    name: &NameInfo,
    out: &mut Classification,
    limit: usize,
) {
    let head = src.head();
    let head = head.get(..limit.min(head.len())).unwrap_or_default();
    let Some((encoding, bom_len)) = detect_encoding(head) else {
        return;
    };
    // A copy, so the tail can be read below. The head is at most 64 KiB.
    let body = head.get(bom_len..).unwrap_or_default().to_vec();
    let body = body.as_slice();
    let text = decode(body, encoding);
    // Two views of the same bytes: decoded in the detected encoding, and as
    // eight-bit text with zero bytes dropped. UTF-16 without a byte order
    // mark is a guess from zero bytes, and eight-bit text padded with zeros
    // can pass for it and decode to unrelated characters; the eight-bit
    // view still shows its markers. For genuine text both views agree on
    // the ASCII markers looked for.
    let view = eight_bit_view(body);
    let guessed = matches!(
        encoding,
        TextEncoding::Utf16LeNoBom | TextEncoding::Utf16BeNoBom
    );
    let is_text = looks_like_text(body, &text, encoding);
    let whole_head = limit >= HEAD_LEN;

    // 1. Definite markers, in either view, whether or not the whole head is
    //    text: binary data before or after a script's text (a
    //    self-extracting script, or bytes added to dodge detection) does
    //    not hide them, and neither does a keyword guess.
    if let Some(found) = best_definite(&text, &view, name) {
        apply(out, encoding, &found);
        if out.flags.script_signature_block {
            return;
        }
        // A signature block may still be at the end of a long file.
        if is_text && whole_head {
            match tail_signature(src, encoding, bom_len, guessed) {
                Ok(Some(_)) => out.flags.script_signature_block = true,
                Ok(None) => {}
                Err(e) => out.parse_error = Some(e),
            }
        }
        return;
    }

    if !is_text {
        // 2. Not text: a script recognised by keywords in its printable
        //    start, or in its content with zeros and a few stray control
        //    bytes removed.
        if let Some(found) = script_prefix(&text)
            .or_else(|| script_prefix(&view))
            .or_else(|| lenient_script(body))
        {
            apply(out, encoding, &found);
        }
        return;
    }

    // 3. Text: a signature block at the end of a long file settles the
    //    language, then keywords decide, in either view.
    out.text_encoding = Some(encoding);
    out.content_kind = FileKind::Text;
    out.confidence = Confidence::High;
    // Only for the whole head: a disc image's system area is classified
    // alone, without the image's contents.
    // A tail that could not be read is reported: a signature block there
    // would have named the language, so the result is not established.
    let tail = if whole_head {
        tail_signature(src, encoding, bom_len, guessed).unwrap_or_else(|e| {
            out.parse_error = Some(e);
            None
        })
    } else {
        None
    };
    if let Some(kind) = tail {
        out.flags.script_signature_block = true;
        out.content_kind = FileKind::Script(kind);
        return;
    }
    let lower = text.to_ascii_lowercase();
    let guess = keywords(&lower).or_else(|| {
        guessed
            .then(|| keywords(&view.to_ascii_lowercase()))
            .flatten()
    });
    if let Some((kind, confidence)) = guess {
        out.content_kind = FileKind::Script(kind);
        out.confidence = confidence;
        out.heuristic = true;
    }
}

/// A signature block marker in the last [`TAIL_LEN`] bytes of a file longer
/// than the head, in the detected encoding or, after a UTF-16 guess, in the
/// eight-bit view. An error if the tail could not be read.
fn tail_signature<R: Read + Seek + ?Sized>(
    src: &mut Source<'_, R>,
    encoding: TextEncoding,
    bom_len: usize,
    guessed: bool,
) -> Result<Option<ScriptKind>, ParseError> {
    if src.len() <= u64::try_from(HEAD_LEN).unwrap_or(u64::MAX) {
        return Ok(None);
    }
    let raw = read_tail(src, encoding, bom_len)?;
    Ok(signature_marker(&decode(&raw, encoding)).or_else(|| {
        guessed
            .then(|| signature_marker(&eight_bit_view(&raw)))
            .flatten()
    }))
}

/// Records what [`definite_in_binary`], [`script_prefix`] or
/// [`lenient_script`] found.
fn apply(out: &mut Classification, encoding: TextEncoding, found: &BinaryFind) {
    out.text_encoding = Some(encoding);
    out.content_kind = found.kind;
    out.confidence = found.confidence;
    out.extension_assisted = found.extension_assisted;
    out.heuristic = found.heuristic;
    out.flags.script_signature_block |= found.signature_block;
    out.flags.encoded_script |= found.encoded;
}

/// The bytes as eight-bit text with every zero byte removed, each byte
/// taken as the character of the same value, so legacy code page bytes
/// stay single characters. For genuine UTF-16 text in the ASCII range this
/// is the same text; for eight-bit text padded to look like UTF-16 it is
/// the eight-bit text.
///
/// A zero byte at the very start is kept as U+FFFD, so markers that must
/// start the file (a shebang line, a registry header) are not found after
/// it: the system would not read them there either. Genuine BOM-less
/// UTF-16 big-endian text starts with a zero too, and is read through its
/// decoded view instead.
fn eight_bit_view(raw: &[u8]) -> String {
    let lead = (raw.first() == Some(&0)).then_some(char::REPLACEMENT_CHARACTER);
    lead.into_iter()
        .chain(raw.iter().filter(|b| **b != 0).map(|b| char::from(*b)))
        .collect()
}

/// Whether a byte is a control byte that text does not use.
fn is_binary_byte(b: u8) -> bool {
    let c = char::from(b);
    (c.is_ascii_control() && !is_text_control(c)) || b == 0x7f
}

/// [`lenient_script`] removes at most one stray control byte (other than
/// zeros) in this many. Binary formats have far more: fonts, images and
/// compressed data run at about one in three, and their bytes can spell
/// short keywords by chance.
const STRAY_RATIO: usize = 20;

/// A script recognised by keywords once zeros and stray control bytes (at
/// most one in [`STRAY_RATIO`] of the rest) are removed: padding, or bytes
/// scattered through a script to dodge detection.
fn lenient_script(raw: &[u8]) -> Option<BinaryFind> {
    let kept: Vec<u8> = raw.iter().copied().filter(|b| *b != 0).collect();
    let stray = kept.iter().filter(|b| is_binary_byte(**b)).count();
    if kept.len() < MIN_PRINTABLE_PREFIX || stray * STRAY_RATIO > kept.len() {
        return None;
    }
    let view: String = kept
        .iter()
        .filter(|b| !is_binary_byte(**b))
        .map(|b| char::from(*b))
        .collect();
    let (kind, confidence) = keywords(&view.to_ascii_lowercase())?;
    Some(BinaryFind {
        kind: FileKind::Script(kind),
        confidence,
        extension_assisted: false,
        heuristic: true,
        signature_block: false,
        encoded: false,
    })
}

/// The printable start of decoded content: everything before the first
/// NUL or ASCII control character that text does not use. Legacy code page
/// bytes (read as U+0080 to U+00FF, or as U+FFFD) do not end it.
fn printable_prefix(text: &str) -> &str {
    let end = text
        .char_indices()
        .find(|(_, c)| c.is_ascii_control() && !is_text_control(*c))
        .map_or(text.len(), |(i, _)| i);
    text.get(..end).unwrap_or_default()
}

/// A script recognised by keywords in the printable start of content that
/// is followed by binary data, as in a self-extracting script or a script
/// padded with zeros.
fn script_prefix(text: &str) -> Option<BinaryFind> {
    let prefix = printable_prefix(text);
    if prefix.trim().chars().count() < MIN_PRINTABLE_PREFIX {
        return None;
    }
    let (kind, confidence) = keywords(&prefix.to_ascii_lowercase())?;
    Some(BinaryFind {
        kind: FileKind::Script(kind),
        confidence,
        extension_assisted: false,
        heuristic: true,
        signature_block: false,
        encoded: false,
    })
}

/// The more confident of the definite markers in the decoded and the
/// eight-bit views, preferring the decoded view on a tie, so a weak marker
/// in one view (such as the encoded script marker) cannot shadow a strong
/// one in the other.
fn best_definite(text: &str, view: &str, name: &NameInfo) -> Option<BinaryFind> {
    match (
        definite_in_binary(text, name),
        definite_in_binary(view, name),
    ) {
        (Some(a), Some(b)) if b.confidence > a.confidence => Some(b),
        (Some(a), _) => Some(a),
        (None, b) => b,
    }
}

/// What [`definite_in_binary`] found.
struct BinaryFind {
    kind: FileKind,
    confidence: Confidence,
    extension_assisted: bool,
    heuristic: bool,
    signature_block: bool,
    encoded: bool,
}

/// A marker in content that is not text as a whole. The same markers as
/// for text are searched across the whole decoded head, so NUL or control
/// bytes before or after them do not hide them; those that must start the
/// file (a shebang line, a registry header) are still anchored there.
/// Signature block markers and the encoded script marker are searched too.
fn definite_in_binary(text: &str, name: &NameInfo) -> Option<BinaryFind> {
    let lower = text.to_ascii_lowercase();
    let signed = signature_marker(text);
    let encoded = lower.contains("#@~^");
    let found = |kind, confidence, extension_assisted, heuristic| BinaryFind {
        kind,
        confidence,
        extension_assisted,
        heuristic,
        signature_block: signed.is_some(),
        encoded,
    };
    if let Some((kind, confidence)) = markers(text, &lower, name) {
        // HTML is an HTML application only because of its `.hta` name.
        let assisted = kind == FileKind::Hta && confidence < Confidence::High;
        return Some(found(kind, confidence, assisted, false));
    }
    if let Some(kind) = signed {
        return Some(found(
            FileKind::Script(kind),
            Confidence::High,
            false,
            false,
        ));
    }
    encoded.then(|| {
        let kind = match name.extension_kind() {
            ExtensionKind::Kind(FileKind::Script(ScriptKind::JScript)) => ScriptKind::JScript,
            _ => ScriptKind::VbScript,
        };
        found(FileKind::Script(kind), Confidence::Medium, false, true)
    })
}

/// Whether the system area in front of a disc image's volume descriptors
/// holds a script rather than boot code or zeros. The system area is
/// free-form, so a script can carry a planted descriptor; such a file
/// stays a script. It does when the file is named as a script or HTML
/// application (the host runs it whatever else is in it), or when the
/// system area is text, has a definite marker in either view, or is a
/// script by keywords as for binary content. A real image's system area is
/// zeros or boot code.
pub(super) fn system_area_is_script(area: &[u8], name: &NameInfo) -> bool {
    if matches!(
        name.extension_kind(),
        ExtensionKind::Kind(FileKind::Script(_) | FileKind::Hta)
    ) {
        return true;
    }
    let Some((encoding, bom_len)) = detect_encoding(area) else {
        return false;
    };
    let body = area.get(bom_len..).unwrap_or_default();
    let text = decode(body, encoding);
    looks_like_text(body, &text, encoding)
        || definite_in_binary(&text, name).is_some()
        || definite_in_binary(&eight_bit_view(body), name).is_some()
        || script_prefix(&text).is_some()
        || script_prefix(&eight_bit_view(body)).is_some()
        || lenient_script(body).is_some()
}

/// The longest shebang line looked past for a ZIP local file header.
const MAX_SHEBANG_LINE: usize = 512;

/// The script kind a `#!` line names, when that line is followed directly
/// by a ZIP local file header. This one byte-level test decides the case:
/// such a file is a zip application or the script the line names, and
/// never depends on how the rest decodes as text (where `markers` takes
/// `#![` for a Rust attribute). A Rust source file has no ZIP header on
/// its second line.
pub(super) fn shebang_zip(head: &[u8]) -> Option<ScriptKind> {
    let nl = head
        .iter()
        .take(MAX_SHEBANG_LINE)
        .position(|b| *b == b'\n')?;
    let interpreter = head.get(..nl)?.strip_prefix(b"#!")?;
    head.get(nl + 1..)?
        .starts_with(b"PK\x03\x04")
        .then(|| shebang(&String::from_utf8_lossy(interpreter)))
}

/// The encoding, and the length of its byte order mark. `None` if the head
/// is empty.
fn detect_encoding(head: &[u8]) -> Option<(TextEncoding, usize)> {
    if head.is_empty() {
        return None;
    }
    // UTF-32 first: its little-endian mark starts with UTF-16's.
    let boms: [(&[u8], TextEncoding); 5] = [
        (&[0xff, 0xfe, 0, 0], TextEncoding::Utf32Le),
        (&[0, 0, 0xfe, 0xff], TextEncoding::Utf32Be),
        (&[0xef, 0xbb, 0xbf], TextEncoding::Utf8Bom),
        (&[0xff, 0xfe], TextEncoding::Utf16Le),
        (&[0xfe, 0xff], TextEncoding::Utf16Be),
    ];
    if let Some((bom, enc)) = boms.iter().find(|(bom, _)| head.starts_with(bom)) {
        return Some((*enc, bom.len()));
    }
    // The whole head is sampled, so a short run of zero-padded bytes at the
    // start cannot decide the encoding for the rest.
    let sample = head;
    let pairs = sample.len() / 2;
    if pairs >= 4 {
        let zeros = |parity: usize| {
            sample
                .iter()
                .skip(parity)
                .step_by(2)
                .take(pairs)
                .filter(|b| **b == 0)
                .count()
        };
        let (even, odd) = (zeros(0), zeros(1));
        // Mostly-ASCII UTF-16: nearly every high byte is zero, and almost
        // no low byte is.
        if odd * 10 >= pairs * 9 && even * 10 <= pairs {
            return Some((TextEncoding::Utf16LeNoBom, 0));
        }
        if even * 10 >= pairs * 9 && odd * 10 <= pairs {
            return Some((TextEncoding::Utf16BeNoBom, 0));
        }
    }
    Some((TextEncoding::EightBit, 0))
}

/// Decodes bytes in `encoding`, replacing anything invalid with U+FFFD. A
/// trailing partial code unit is dropped.
fn decode(data: &[u8], encoding: TextEncoding) -> String {
    match encoding {
        TextEncoding::EightBit | TextEncoding::Utf8Bom => {
            String::from_utf8_lossy(data).into_owned()
        }
        TextEncoding::Utf16Le | TextEncoding::Utf16LeNoBom => utf16(data, u16::from_le_bytes),
        TextEncoding::Utf16Be | TextEncoding::Utf16BeNoBom => utf16(data, u16::from_be_bytes),
        TextEncoding::Utf32Le => utf32(data, u32::from_le_bytes),
        TextEncoding::Utf32Be => utf32(data, u32::from_be_bytes),
    }
}

fn utf16(data: &[u8], unit: fn([u8; 2]) -> u16) -> String {
    let units = data.chunks_exact(2).map(|c| {
        unit([
            c.first().copied().unwrap_or(0),
            c.get(1).copied().unwrap_or(0),
        ])
    });
    char::decode_utf16(units)
        .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

fn utf32(data: &[u8], unit: fn([u8; 4]) -> u32) -> String {
    data.chunks_exact(4)
        .map(|c| {
            let mut word = [0_u8; 4];
            word.copy_from_slice(c);
            char::from_u32(unit(word)).unwrap_or(char::REPLACEMENT_CHARACTER)
        })
        .collect()
}

/// Whether content is text. Eight-bit content is judged on its bytes, so
/// legacy code pages pass and binary data does not: no NUL, and at most one
/// control byte in a hundred. Wider encodings are judged on the decoded
/// characters, counting invalid code units as control characters.
fn looks_like_text(raw: &[u8], text: &str, encoding: TextEncoding) -> bool {
    let allowed = is_text_control;
    let (total, control) = if matches!(encoding, TextEncoding::EightBit | TextEncoding::Utf8Bom) {
        if raw.contains(&0) {
            return false;
        }
        let control = raw
            .iter()
            .filter(|b| {
                let c = char::from(**b);
                (c.is_ascii_control() && !allowed(c)) || **b == 0x7f
            })
            .count();
        (raw.len(), control)
    } else {
        let mut total = 0_usize;
        let mut control = 0_usize;
        for c in text.chars() {
            total += 1;
            if (c.is_control() && !allowed(c)) || c == char::REPLACEMENT_CHARACTER {
                control += 1;
            }
        }
        (total, control)
    };
    total > 0 && control * 100 <= total
}

/// Control characters that are normal in text: tab, line feed, form feed,
/// carriage return, escape and the DOS end-of-file mark.
const fn is_text_control(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\x0c' | '\r' | '\x1b' | '\x1a')
}

/// Reads the last [`TAIL_LEN`] bytes, aligned to the encoding's code unit.
fn read_tail<R: Read + Seek + ?Sized>(
    src: &mut Source<'_, R>,
    encoding: TextEncoding,
    bom_len: usize,
) -> Result<Vec<u8>, ParseError> {
    let unit: u64 = match encoding {
        TextEncoding::EightBit | TextEncoding::Utf8Bom => 1,
        TextEncoding::Utf32Le | TextEncoding::Utf32Be => 4,
        _ => 2,
    };
    // Both fit in a `u64` on every supported target.
    let bom = u64::try_from(bom_len).unwrap_or(u64::MAX);
    let tail = u64::try_from(TAIL_LEN).unwrap_or(u64::MAX);
    let start = src.len().saturating_sub(tail).max(bom);
    // Align to a code unit boundary counted from the end of the mark.
    let start = start + (unit - (start - bom) % unit) % unit;
    Ok(src.read_at(start, TAIL_LEN)?)
}

/// Script signature block markers, and the language each one is for.
const SIGNATURE_MARKERS: [(&str, ScriptKind); 4] = [
    ("# SIG # Begin signature block", ScriptKind::PowerShell),
    ("'' SIG '' Begin signature block", ScriptKind::VbScript),
    ("// SIG // Begin signature block", ScriptKind::JScript),
    ("** SIG ** Begin signature block", ScriptKind::Wsf),
];

fn signature_marker(text: &str) -> Option<ScriptKind> {
    SIGNATURE_MARKERS
        .iter()
        .find(|(marker, _)| text.contains(marker))
        .map(|(_, kind)| *kind)
}

/// Definite markers: shebang lines, file headers and defining elements.
fn markers(text: &str, lower: &str, name: &NameInfo) -> Option<(FileKind, Confidence)> {
    let high = |kind| Some((kind, Confidence::High));
    let first_line = text
        .lines()
        .next()
        .unwrap_or_default()
        .trim_start_matches('\u{feff}');
    // `#![` starts a Rust inner attribute, which the Rust reference does
    // not take as a shebang line. As a shebang it would name a relative
    // interpreter path starting with `[`, which no real script does. Such
    // a file still goes through the keyword and name rules below.
    if let Some(interpreter) = first_line.strip_prefix("#!")
        && !interpreter.trim_start().starts_with('[')
    {
        return high(FileKind::Script(shebang(interpreter)));
    }
    let start = lower.trim_start();
    if start.starts_with("windows registry editor version 5.00") || start.starts_with("regedit4") {
        return high(FileKind::Reg);
    }
    if lower.contains("<hta:application") {
        return high(FileKind::Hta);
    }
    if lower.contains("<?php") {
        return high(FileKind::Script(ScriptKind::Php));
    }
    if lower.contains("<scriptlet")
        || (lower.contains("<component") && lower.contains("<registration"))
    {
        return high(FileKind::Script(ScriptKind::Wsc));
    }
    // The `language` attribute is optional (it defaults to VBScript), as is
    // inline code (`<script src="..."/>`).
    if lower.contains("<job") && lower.contains("<script") {
        return high(FileKind::Script(ScriptKind::Wsf));
    }
    let xsl = lower.contains("<xsl:stylesheet") || lower.contains("<xsl:transform");
    if xsl && (lower.contains(":script") || lower.contains("<script")) {
        return high(FileKind::Script(ScriptKind::Xsl));
    }
    if lower.contains("<pcsettings") && lower.contains("<deeplink") {
        return high(FileKind::Script(ScriptKind::SettingContent));
    }
    if lower.contains("[version]")
        && (lower.contains("$windows nt$") || lower.contains("$chicago$"))
    {
        return high(FileKind::Script(ScriptKind::Inf));
    }
    // Last: HTML is an HTML application only because of its `.hta` name,
    // so every marker above, which the content defines, comes first.
    let html = [
        "<html",
        "<!doctype html",
        "<head",
        "<body",
        "<script",
        "<svg",
        "<iframe",
        "<object",
        "<embed",
        "<img",
    ]
    .iter()
    .any(|tag| lower.contains(tag));
    (html && name.is_ext(&["hta"])).then_some((FileKind::Hta, Confidence::Medium))
}

/// The script kind a shebang line's interpreter names. The interpreter is
/// the program's file name, or the first argument of `env` (after any `-S`
/// or other options), with version suffixes ignored.
fn shebang(line: &str) -> ScriptKind {
    let mut words = line.split_whitespace();
    let program = words.next().unwrap_or_default();
    let file = |path: &'_ str| -> String {
        let base = path
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        base.strip_suffix(".exe").map(str::to_owned).unwrap_or(base)
    };
    let mut base = file(program);
    if base == "env" {
        base = file(env_command(words).unwrap_or_default());
    }
    let stem = base.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    match stem {
        "python" | "pypy" => ScriptKind::Python,
        "pwsh" | "powershell" => ScriptKind::PowerShell,
        "perl" => ScriptKind::Perl,
        "ruby" => ScriptKind::Ruby,
        "php" => ScriptKind::Php,
        "node" | "nodejs" | "deno" | "bun" => ScriptKind::JScript,
        _ => ScriptKind::Shell,
    }
}

/// The command `env` runs, given its arguments: the first word that is not
/// an option, an option's operand or a `NAME=VALUE` assignment. `-u`, `-C`,
/// `-P` and `-a` (and `--unset`, `--chdir` and `--argv0`) take an operand,
/// in the same word or the next. `-S` takes the rest of the line, already
/// split into words here, so the command follows it as for any option; a
/// command written in the same word (`-Spython3`, `--split-string=python3`)
/// is that command.
fn env_command<'a>(mut words: impl Iterator<Item = &'a str>) -> Option<&'a str> {
    const SHORT_WITH_OPERAND: [char; 4] = ['u', 'C', 'P', 'a'];
    const LONG_WITH_OPERAND: [&str; 3] = ["unset", "chdir", "argv0"];
    while let Some(word) = words.next() {
        if word == "--" {
            return words.find(|w| !w.contains('='));
        }
        if let Some(long) = word.strip_prefix("--") {
            if let Some(command) = long.strip_prefix("split-string=") {
                return Some(command);
            }
            if LONG_WITH_OPERAND.contains(&long) {
                words.next();
            }
            continue;
        }
        if let Some(cluster) = word.strip_prefix('-') {
            for (i, c) in cluster.char_indices() {
                let rest = cluster.get(i + c.len_utf8()..).unwrap_or_default();
                if c == 'S' && !rest.is_empty() {
                    return Some(rest);
                }
                if SHORT_WITH_OPERAND.contains(&c) {
                    // The operand is the rest of this word, or the next.
                    if rest.is_empty() {
                        words.next();
                    }
                    break;
                }
            }
            continue;
        }
        if !word.contains('=') {
            return Some(word);
        }
    }
    None
}

/// Keywords per language. Each counts once however often it appears.
const KEYWORDS: &[(ScriptKind, &[&str])] = &[
    (
        ScriptKind::PowerShell,
        &[
            "param(",
            "[cmdletbinding(",
            "write-host",
            "write-output",
            "get-childitem",
            "get-item",
            "set-item",
            "new-object",
            "invoke-",
            "$psscriptroot",
            "$env:",
            "-erroraction",
            "foreach-object",
            "where-object",
            "[string]$",
            "$true",
            "$false",
            "$null",
        ],
    ),
    (
        ScriptKind::Batch,
        &[
            "@echo off",
            "setlocal",
            "endlocal",
            "%~dp0",
            "%errorlevel%",
            "if errorlevel",
            "goto :",
            "goto end",
            "call :",
            "set /a",
            "set /p",
            "rem ",
            "exit /b",
        ],
    ),
    (
        ScriptKind::VbScript,
        &[
            "dim ",
            "end sub",
            "end function",
            "on error resume next",
            "createobject(",
            "wscript.echo",
            "wscript.shell",
            "msgbox",
            "end if",
            "set obj",
        ],
    ),
    (
        ScriptKind::JScript,
        &[
            "var ",
            "new activexobject(",
            "function(",
            "function (",
            "===",
            "!==",
            "console.log(",
            "require(",
            "=> {",
            "wscript.createobject(",
        ],
    ),
    (
        ScriptKind::Python,
        &[
            "import os",
            "import sys",
            "if __name__ == '__main__'",
            "if __name__ == \"__main__\"",
            "def __init__(self",
            "elif ",
            "print(",
            "self.",
            "except exception",
        ],
    ),
    (
        ScriptKind::Perl,
        &[
            "use strict;",
            "use warnings;",
            "my $",
            "my @",
            "my %",
            "sub {",
            "$_",
        ],
    ),
    (
        ScriptKind::Ruby,
        &[
            "require '",
            "puts ",
            ".each do |",
            "attr_accessor",
            "end\n",
            "def initialize",
        ],
    ),
    (
        ScriptKind::Shell,
        &[
            "\nfi\n", "esac", "then\n", "export ", "echo \"$", "${", "$(", "; do",
        ],
    ),
];

/// Hits needed for a low-confidence guess, and for a medium one.
const LOW_HITS: usize = 2;
const MEDIUM_HITS: usize = 4;

/// The best keyword match, if one language clearly leads.
fn keywords(lower: &str) -> Option<(ScriptKind, Confidence)> {
    let mut scores: Vec<(ScriptKind, usize)> = KEYWORDS
        .iter()
        .map(|(kind, words)| (*kind, words.iter().filter(|w| lower.contains(*w)).count()))
        .collect();
    scores.sort_by_key(|s| std::cmp::Reverse(s.1));
    let (kind, best) = *scores.first()?;
    let runner_up = scores.get(1).map_or(0, |s| s.1);
    // A tie is no answer.
    if best < LOW_HITS || best == runner_up {
        return None;
    }
    let confidence = if best >= MEDIUM_HITS && best >= runner_up * 2 {
        Confidence::Medium
    } else {
        Confidence::Low
    };
    Some((kind, confidence))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shebangs() {
        assert_eq!(shebang("/usr/bin/env python3"), ScriptKind::Python);
        assert_eq!(shebang("/usr/bin/python3.12 -u"), ScriptKind::Python);
        assert_eq!(
            shebang("/usr/bin/env -S pwsh -NoProfile"),
            ScriptKind::PowerShell
        );
        assert_eq!(shebang("/usr/bin/env LANG=C perl"), ScriptKind::Perl);
        assert_eq!(shebang("/bin/sh"), ScriptKind::Shell);
        assert_eq!(shebang(" /usr/local/bin/node"), ScriptKind::JScript);
        assert_eq!(shebang(""), ScriptKind::Shell);
        assert_eq!(shebang("/usr/bin/env"), ScriptKind::Shell);
        assert_eq!(shebang(r"C:\Python312\python.exe"), ScriptKind::Python);
        assert_eq!(shebang(r"C:\tools\PWSH.EXE -File"), ScriptKind::PowerShell);
    }

    #[test]
    fn env_option_operands_are_skipped() {
        // Review round 15: the operand of `-u` was taken for the command.
        assert_eq!(
            shebang("/usr/bin/env -S -u PYTHONPATH python3"),
            ScriptKind::Python
        );
        assert_eq!(
            shebang("/usr/bin/env -uPYTHONPATH python3"),
            ScriptKind::Python
        );
        assert_eq!(shebang("/usr/bin/env -iu X perl"), ScriptKind::Perl);
        assert_eq!(shebang("/usr/bin/env -C /tmp ruby"), ScriptKind::Ruby);
        assert_eq!(
            shebang("/usr/bin/env -P /opt/bin node"),
            ScriptKind::JScript
        );
        assert_eq!(
            shebang("/usr/bin/env --unset PERL5LIB perl"),
            ScriptKind::Perl
        );
        assert_eq!(
            shebang("/usr/bin/env --unset=PERL5LIB perl"),
            ScriptKind::Perl
        );
        assert_eq!(shebang("/usr/bin/env -Spython3 -u"), ScriptKind::Python);
        assert_eq!(
            shebang("/usr/bin/env --split-string=pwsh -NoProfile"),
            ScriptKind::PowerShell
        );
        assert_eq!(shebang("/usr/bin/env -i -- A=1 php"), ScriptKind::Php);
        assert_eq!(shebang("/usr/bin/env -S python3"), ScriptKind::Python);
        assert_eq!(shebang("/usr/bin/env -u"), ScriptKind::Shell);
    }

    #[test]
    fn encodings() {
        assert_eq!(detect_encoding(b""), None);
        assert_eq!(
            detect_encoding(&[0xff, 0xfe, 0, 0, b'a', 0, 0, 0]),
            Some((TextEncoding::Utf32Le, 4))
        );
        assert_eq!(
            detect_encoding(&[0xff, 0xfe, b'a', 0]),
            Some((TextEncoding::Utf16Le, 2))
        );
        let le: Vec<u8> = "hello world"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(detect_encoding(&le), Some((TextEncoding::Utf16LeNoBom, 0)));
        let be: Vec<u8> = "hello world"
            .encode_utf16()
            .flat_map(u16::to_be_bytes)
            .collect();
        assert_eq!(detect_encoding(&be), Some((TextEncoding::Utf16BeNoBom, 0)));
        assert_eq!(decode(&le, TextEncoding::Utf16LeNoBom), "hello world");
        assert_eq!(decode(&[0, 0, 0, b'x', 0, 0], TextEncoding::Utf32Be), "x");
        assert_eq!(
            decode(&[0xff, 0xff, 0xff, 0x7f], TextEncoding::Utf32Le),
            "\u{fffd}"
        );
    }

    #[test]
    fn binary_is_not_text() {
        let eight = |s: &str| looks_like_text(s.as_bytes(), s, TextEncoding::EightBit);
        assert!(!eight("ab\0cd"));
        let noisy: String = (0..100)
            .map(|i| if i % 10 == 0 { '\x01' } else { 'a' })
            .collect();
        assert!(!eight(&noisy));
        assert!(eight("line one\r\nline two\t\x1a"));
        assert!(!eight(""));
        // A legacy code page byte is fine.
        assert!(looks_like_text(
            b"caf\xe9",
            "caf\u{fffd}",
            TextEncoding::EightBit
        ));
        // Invalid UTF-16 is not.
        let bad: String = std::iter::repeat_n('\u{fffd}', 10).collect();
        assert!(!looks_like_text(&[], &bad, TextEncoding::Utf16Le));
    }

    #[test]
    fn keyword_guesses() {
        assert_eq!(
            keywords("@echo off\nsetlocal\nset /a x=1\ngoto :eof\nexit /b 0"),
            Some((ScriptKind::Batch, Confidence::Medium))
        );
        assert_eq!(
            keywords("dim x\nmsgbox x"),
            Some((ScriptKind::VbScript, Confidence::Low))
        );
        assert_eq!(keywords("hello world"), None);
        // One hit is not enough.
        assert_eq!(keywords("print(1)"), None);
    }
}
