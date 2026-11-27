//! Reads YAML text into a tree of located nodes, applying the strict rules
//! described in [the module docs](super).

use std::cell::Cell;
use std::collections::HashMap;
use std::collections::hash_map::Entry as Slot;
use std::rc::Rc;

use yaml_rust2::parser::{Event, Parser};
use yaml_rust2::scanner::{Marker, ScanError, TScalarStyle};

use super::{Limits, Location, YamlError, YamlErrorKind};

/// One node of the document and the position where it starts.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Node {
    pub(crate) value: Value,
    pub(crate) location: Location,
}

/// The value of a node. Plain scalars are typed here, once, by
/// [`resolve_plain`]; quoted and block scalars are always text.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Value {
    Null,
    Bool(bool),
    /// A non-negative integer.
    UInt(u64),
    /// A negative integer.
    NegInt(i64),
    /// A finite number with a fraction or an exponent.
    Float(f64),
    /// A JSON number too large for the types above, as written. It is
    /// resolved when used, as serde_json resolves it: the nearest float if
    /// it has one, otherwise an error with the field's path.
    OutOfRange(String),
    Str(String),
    Seq(Vec<Node>),
    Map(Map),
}

/// A map's entries in source order, with an index by key.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Map {
    pub(crate) entries: Vec<Entry>,
    /// The position in `entries` of each key, so looking a key up does not
    /// depend on the size of the map.
    index: HashMap<String, usize>,
}

impl Map {
    pub(crate) fn get(&self, key: &str) -> Option<&Entry> {
        self.index.get(key).and_then(|&i| self.entries.get(i))
    }
}

/// One key and value of a map. Keys are always text.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Entry {
    pub(crate) key: String,
    pub(crate) key_location: Location,
    pub(crate) value: Node,
}

/// Parses a YAML stream of one or more documents separated by `---`, and
/// passes each document's root to `on_document` as soon as the document
/// ends, so an error in an earlier document is reported before any problem
/// in a later one. With `single`, a second document is an error.
pub(crate) fn parse(
    input: &str,
    limits: &Limits,
    single: bool,
    on_document: impl FnMut(Node) -> Result<(), YamlError>,
) -> Result<(), YamlError> {
    parse_with(input, limits, single, true, on_document)
}

/// [`parse`], with the JSON fast path optional, so tests can compare both
/// readers on the same JSON text.
pub(crate) fn parse_with(
    input: &str,
    limits: &Limits,
    single: bool,
    json_fast_path: bool,
    mut on_document: impl FnMut(Node) -> Result<(), YamlError>,
) -> Result<(), YamlError> {
    if input.len() > limits.max_bytes {
        return Err(YamlError::new(
            YamlErrorKind::LimitExceeded,
            format!(
                "the input is {} bytes; at most {} are allowed",
                input.len(),
                limits.max_bytes
            ),
        ));
    }
    // A byte order mark may start the stream (YAML 1.2 section 5.2). The
    // parser would otherwise read it as part of the first key.
    let input = input.strip_prefix('\u{feff}').unwrap_or(input);
    // The whole input is checked for disallowed characters before any of it
    // is parsed, and the first one is reported ahead of every other problem.
    // The check cannot be made per document: the parser stops silently at
    // U+0000, as if the input ended there, so text after a NUL would never
    // be seen, and a document cut short by one could look complete. Nor can
    // the parser be given a copy with the character replaced, because any
    // replacement is YAML syntax to it (`---\0` would become `--- `). The
    // cost is that, in a stream, a disallowed character in a later document
    // is reported before a model error in an earlier one.
    check_characters(input)?;

    let mut builder = Builder {
        limits,
        stack: Vec::new(),
        roots: Vec::new(),
        nodes: 0,
    };
    if json_fast_path && is_json(input, limits.max_depth) {
        json::read(input, &mut builder)?;
        let mut finished = 0usize;
        for root in builder.roots.drain(..) {
            finished += 1;
            on_document(root)?;
        }
        return if finished == 1 {
            Ok(())
        } else {
            Err(internal(Location { line: 1, column: 1 }))
        };
    }
    let mut prefix = Prefix::new(input);
    let budget = Rc::new(Cell::new(0usize));
    let mut parser = Parser::new(Budgeted {
        chars: input.chars(),
        budget: Rc::clone(&budget),
    });
    let mut documents = 0usize;
    let mut finished = 0usize;
    let mut last = Location { line: 1, column: 1 };
    loop {
        // The parser may queue many tokens before it returns an event (see
        // `Budgeted`), so the characters it reads for one event are bounded.
        budget.set(limits.max_lookahead.saturating_add(1));
        let next = parser.next_token();
        if budget.get() == 0 {
            return Err(lookahead_exceeded(limits, last));
        }
        let (event, mark) = next.map_err(|e| scan_error(&e))?;
        let at = location(mark);
        last = at;
        match event {
            Event::StreamEnd => break,
            Event::DocumentStart => {
                prefix.check(mark.line())?;
                documents += 1;
                if single && documents > 1 {
                    return Err(YamlError::new(
                        YamlErrorKind::UnsupportedFeature,
                        "a second document starts here; this reads one document (use `from_str_all` for a stream)",
                    )
                    .at(at));
                }
            }
            Event::DocumentEnd => prefix.skip_to(mark.line()),
            Event::Nothing | Event::StreamStart => {}
            Event::Alias(_) => {
                return Err(YamlError::new(
                    YamlErrorKind::UnsupportedFeature,
                    "aliases (`*name`) are not supported",
                )
                .at(at));
            }
            Event::Scalar(text, style, anchor, tag) => {
                properties(anchor, tag.is_some(), at)?;
                builder.scalar(text, style == TScalarStyle::Plain, at)?;
            }
            Event::SequenceStart(anchor, tag) => {
                properties(anchor, tag.is_some(), at)?;
                builder.open(false, at)?;
            }
            Event::MappingStart(anchor, tag) => {
                // A block map's marker is inside its first key, so the error
                // is reported once the first key shows where the map starts.
                let property = properties(anchor, tag.is_some(), at).err();
                builder.open(true, at)?;
                if let (Some(error), Some(Frame::Map { pending, .. })) =
                    (property, builder.stack.last_mut())
                {
                    *pending = Some(error);
                }
            }
            Event::SequenceEnd | Event::MappingEnd => builder.close()?,
        }
        for root in builder.roots.drain(..) {
            finished += 1;
            on_document(root)?;
        }
    }
    if finished == 0 {
        return Err(YamlError::new(
            YamlErrorKind::Syntax,
            "the input holds no YAML document; expected a policy document",
        )
        .at(Location { line: 1, column: 1 }));
    }
    Ok(())
}

/// Whether the input is a JSON object or array, which [`json::read`] reads
/// instead of the YAML parser.
///
/// Every JSON text is also YAML 1.2 with the same meaning, but the YAML
/// parser reads a flow collection that starts a line, or follows `[` or
/// `,`, whole before it reports anything (see [`Budgeted`]), and that is
/// every object in a JSON array. Valid JSON is read with a streaming
/// tokenizer instead, through the same [`Builder`], so the same limits,
/// duplicate-key and typing rules apply. The check is a full JSON parse
/// that keeps nothing, so a text that only starts like JSON goes to the
/// YAML parser as before.
///
/// Before that parse, the nesting depth is counted outside strings and
/// checked against `max_depth`: serde_json's own check of an ignored value
/// keeps one byte per open collection and does not use its recursion
/// limit. Too deep an input is left to the YAML parser, which reports it
/// at the first level over the limit.
pub(crate) fn is_json(input: &str, max_depth: usize) -> bool {
    matches!(
        input
            .trim_start_matches([' ', '\t', '\n', '\r'])
            .as_bytes()
            .first(),
        Some(b'{' | b'[')
    ) && json_depth_within(input, max_depth)
        && serde_json::from_str::<serde::de::IgnoredAny>(input).is_ok()
}

/// Whether `[` and `{` outside JSON strings never nest deeper than
/// `max_depth`. Brackets need not balance; the full parse checks that.
fn json_depth_within(input: &str, max_depth: usize) -> bool {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for b in input.bytes() {
        if in_string {
            match (escaped, b) {
                (true, _) => escaped = false,
                (false, b'\\') => escaped = true,
                (false, b'"') => in_string = false,
                _ => {}
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'[' | b'{' => {
                depth += 1;
                if depth > max_depth {
                    return false;
                }
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    true
}

/// Reads a JSON text that is known to be valid, as [`Builder`] events.
mod json {
    use super::{Builder, Location, YamlError, internal};

    /// Reads `input`, which [`super::is_json`] accepted.
    pub(super) fn read(input: &str, builder: &mut Builder<'_>) -> Result<(), YamlError> {
        let mut cursor = Cursor {
            rest: input,
            line: 1,
            column: 1,
            after_cr: false,
        };
        loop {
            cursor.skip_whitespace();
            let at = cursor.location();
            let Some(c) = cursor.rest.chars().next() else {
                return Ok(());
            };
            match c {
                '{' | '[' => {
                    cursor.advance(1);
                    builder.open(c == '{', at)?;
                }
                '}' | ']' => {
                    cursor.advance(1);
                    builder.close()?;
                }
                ',' | ':' => cursor.advance(1),
                '"' => {
                    let len = string_len(cursor.rest).ok_or_else(|| internal(at))?;
                    let literal = cursor.rest.get(..len).ok_or_else(|| internal(at))?;
                    // serde_json decodes escapes, including surrogate pairs.
                    let text: String = serde_json::from_str(literal).map_err(|_| internal(at))?;
                    cursor.advance(len);
                    builder.scalar(text, false, at)?;
                }
                _ => {
                    // A number, `true`, `false` or `null`, typed as a plain
                    // scalar, as the YAML parser would.
                    let len = cursor
                        .rest
                        .find([',', ']', '}', ' ', '\t', '\n', '\r'])
                        .unwrap_or(cursor.rest.len());
                    let text = cursor.rest.get(..len).ok_or_else(|| internal(at))?;
                    let text = text.to_owned();
                    cursor.advance(len);
                    builder.scalar(text, true, at)?;
                }
            }
        }
    }

    /// The byte length of the string literal at the start of `s`, quotes
    /// included.
    fn string_len(s: &str) -> Option<usize> {
        let bytes = s.as_bytes();
        let mut i = 1;
        while let Some(&b) = bytes.get(i) {
            match b {
                b'"' => return Some(i + 1),
                b'\\' => i += 2,
                _ => i += 1,
            }
        }
        None
    }

    struct Cursor<'a> {
        rest: &'a str,
        line: usize,
        column: usize,
        after_cr: bool,
    }

    impl Cursor<'_> {
        const fn location(&self) -> Location {
            Location {
                line: self.line,
                column: self.column,
            }
        }

        /// Moves past `len` bytes, counting lines as the YAML parser does.
        fn advance(&mut self, len: usize) {
            let (done, rest) = self.rest.split_at(len.min(self.rest.len()));
            for c in done.chars() {
                match c {
                    '\n' if self.after_cr => {}
                    '\n' | '\r' => {
                        self.line += 1;
                        self.column = 1;
                    }
                    _ => self.column += 1,
                }
                self.after_cr = c == '\r';
            }
            self.rest = rest;
        }

        fn skip_whitespace(&mut self) {
            let len = self.rest.len() - self.rest.trim_start_matches([' ', '\t', '\n', '\r']).len();
            self.advance(len);
        }
    }
}

/// The characters of the input, metered for one parser event at a time.
///
/// `yaml-rust2` 0.13.2 reads a flow collection that starts a line, or that
/// follows `[` or `,`, to its end before it reports the collection's first
/// value, because the collection might still turn out to be a mapping key.
/// It does not give up on that possibility after 1024 characters inside a
/// flow collection, so without a bound one wide collection (`[1,1,1,...]`)
/// is queued as tokens, roughly 100 bytes per input character, before
/// [`Builder`] counts a single node. The tokens queued at any time come
/// from at most one such read, so the budget bounds their memory. When the budget runs out the
/// parser sees the end of the input, and [`parse`] reports
/// `yaml_limit_exceeded` instead of whatever the parser makes of that.
struct Budgeted<'a> {
    chars: core::str::Chars<'a>,
    /// Characters left for the current event, plus one. Zero means the
    /// budget ran out.
    budget: Rc<Cell<usize>>,
}

impl Iterator for Budgeted<'_> {
    type Item = char;

    fn next(&mut self) -> Option<char> {
        // The real end of the input never uses up the budget, so an event
        // that ends exactly at the limit is not misreported.
        if self.chars.as_str().is_empty() {
            return None;
        }
        match self.budget.get() {
            0 => None,
            1 => {
                self.budget.set(0);
                None
            }
            n => {
                self.budget.set(n - 1);
                self.chars.next()
            }
        }
    }
}

fn lookahead_exceeded(limits: &Limits, after: Location) -> YamlError {
    YamlError::new(
        YamlErrorKind::LimitExceeded,
        format!(
            "the parser read more than {} characters to find the next value. A scalar this \
             long, or a flow collection (`[...]` or `{{...}}`) that starts a line or follows \
             `[` or `,`, is read whole first; write large collections in block style",
            limits.max_lookahead
        ),
    )
    .at(after)
}

/// The parser's marker as a 1-based line and column.
fn location(mark: Marker) -> Location {
    Location {
        line: mark.line(),
        column: mark.col().saturating_add(1),
    }
}

fn scan_error(e: &ScanError) -> YamlError {
    // The scanner's own cap on flow nesting (255 levels) is a limit, not a
    // syntax error. It can only be reached when [`Limits::max_depth`] is
    // higher, or before the first event of a deep collection reaches it.
    let kind = if e.info() == "recursion limit exceeded" {
        YamlErrorKind::LimitExceeded
    } else {
        YamlErrorKind::Syntax
    };
    YamlError::new(kind, e.info().to_owned()).at(location(*e.marker()))
}

/// Anchors and tags are rejected wherever they appear. The error points at
/// the value that carries them, because the parser does not report where
/// the property itself starts. Without anchors there are no aliases, so no
/// "billion laughs" expansion is possible.
fn properties(anchor: usize, tagged: bool, at: Location) -> Result<(), YamlError> {
    if anchor != 0 {
        return Err(YamlError::new(
            YamlErrorKind::UnsupportedFeature,
            "anchors (`&name`) are not supported",
        )
        .at(at));
    }
    if tagged {
        return Err(YamlError::new(
            YamlErrorKind::UnsupportedFeature,
            "tags (`!name`) are not supported; to make a scalar text, quote it instead",
        )
        .at(at));
    }
    Ok(())
}

/// Whether a character may appear unescaped in the text.
///
/// This is the YAML 1.2 printable set (section 5.1, which excludes the
/// byte order mark U+FEFF) without U+0085, U+2028 and U+2029. A byte order
/// mark at the very start of the input is removed before this check. YAML 1.1 readers treat those as line breaks and
/// YAML 1.2 readers do not, so in a comment they would hide or reveal the
/// rest of the line depending on the reader. They can still be written as
/// escapes in double-quoted strings. The parser stops silently at U+0000,
/// so this check must run before it.
const fn is_allowed(c: char) -> bool {
    matches!(c,
        '\t' | '\n' | '\r' | '\u{20}'..='\u{7e}'
        | '\u{a0}'..='\u{2027}' | '\u{202a}'..='\u{d7ff}' | '\u{e000}'..='\u{fefe}'
        | '\u{ff00}'..='\u{fffd}'
        | '\u{10000}'..='\u{10ffff}')
}

/// Rejects the input if it holds a character that may not appear
/// unescaped ([`is_allowed`]), at the first one. See [`parse_with`] for why
/// this covers the whole input.
fn check_characters(input: &str) -> Result<(), YamlError> {
    match input.char_indices().find(|&(_, c)| !is_allowed(c)) {
        None => Ok(()),
        Some((index, c)) => Err(YamlError::new(
            YamlErrorKind::Syntax,
            format!(
                "character U+{:04X} is not allowed unescaped; write it as an escape in a double-quoted string",
                u32::from(c)
            ),
        )
        .at(location_of(input, index))),
    }
}

/// The line and column of a byte offset, counting line breaks as the
/// parser does: LF, CRLF or a lone CR.
fn location_of(input: &str, offset: usize) -> Location {
    let mut line = 1usize;
    let mut column = 1usize;
    let mut after_cr = false;
    for c in input.get(..offset).unwrap_or("").chars() {
        match c {
            '\n' if after_cr => {}
            '\n' | '\r' => {
                line += 1;
                column = 1;
            }
            _ => column += 1,
        }
        after_cr = c == '\r';
    }
    Location { line, column }
}

/// Checks the directives before each document: only `%YAML 1.2` is
/// allowed, so `%TAG`, other versions and reserved directives are rejected.
///
/// The parser applies directives without reporting them. They can only
/// appear in a document's prefix: the lines from the end of the previous
/// document (or the start of the stream) up to the line of the `---` that
/// starts the document, and only at the start of a line. This reads those
/// lines from the source as document events arrive, so the input is read
/// once more in total and never ahead of the parser's own limits.
///
/// Positions are tracked by line. The parser's line numbers are exact,
/// but its character index is not: after a long block-scalar line it
/// counts that line in bytes.
struct Prefix<'a> {
    lines: Lines<'a>,
    /// The 1-based number of the next line `lines` yields.
    next_line: usize,
}

impl<'a> Prefix<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            lines: Lines(input),
            next_line: 1,
        }
    }

    /// A document ended on `line`; the next prefix starts there.
    fn skip_to(&mut self, line: usize) {
        while self.next_line < line && self.lines.next().is_some() {
            self.next_line += 1;
        }
    }

    /// A document starts on `line`: check the lines before it.
    fn check(&mut self, line: usize) -> Result<(), YamlError> {
        while self.next_line < line {
            let Some(text) = self.lines.next() else {
                break;
            };
            let number = self.next_line;
            self.next_line += 1;
            let Some(directive) = text.strip_prefix('%') else {
                continue;
            };
            let mut words = directive
                .split('#')
                .next()
                .unwrap_or("")
                .split_ascii_whitespace();
            let message = match (words.next(), words.next(), words.next()) {
                (Some("YAML"), Some("1.2"), None) => continue,
                (Some("TAG"), ..) => "tag directives (`%TAG`) are not supported".to_owned(),
                _ => format!(
                    "only the `%YAML 1.2` directive is supported; found `%{}`",
                    directive.trim_end()
                ),
            };
            return Err(
                YamlError::new(YamlErrorKind::UnsupportedFeature, message).at(Location {
                    line: number,
                    column: 1,
                }),
            );
        }
        Ok(())
    }
}

/// The lines of a text without their breaks, splitting at LF, CRLF or a
/// lone CR, as the parser and [`location_of`] count them.
struct Lines<'a>(&'a str);

impl<'a> Iterator for Lines<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<&'a str> {
        if self.0.is_empty() {
            return None;
        }
        let (line, rest) = match self.0.find(['\n', '\r']) {
            None => (self.0, ""),
            Some(i) => {
                let rest = self.0.get(i..).unwrap_or("");
                let skip = if rest.starts_with("\r\n") { 2 } else { 1 };
                (
                    self.0.get(..i).unwrap_or(""),
                    rest.get(skip..).unwrap_or(""),
                )
            }
        };
        self.0 = rest;
        Some(line)
    }
}

enum Frame {
    Seq {
        location: Location,
        items: Vec<Node>,
    },
    Map {
        location: Location,
        entries: Vec<Entry>,
        /// The key whose value is being read.
        key: Option<(String, Location)>,
        /// The position in `entries` of every key so far.
        index: HashMap<String, usize>,
        /// An anchor or tag on the map, reported at the map's start.
        pending: Option<YamlError>,
    },
}

/// Builds the tree from parser events with an explicit stack, so input
/// depth never becomes call depth here.
struct Builder<'l> {
    limits: &'l Limits,
    stack: Vec<Frame>,
    /// One node per finished document.
    roots: Vec<Node>,
    nodes: usize,
}

impl Builder<'_> {
    fn count(&mut self, at: Location) -> Result<(), YamlError> {
        self.nodes += 1;
        if self.nodes > self.limits.max_nodes {
            return Err(YamlError::new(
                YamlErrorKind::LimitExceeded,
                format!("the document has more than {} nodes", self.limits.max_nodes),
            )
            .at(at));
        }
        Ok(())
    }

    fn scalar(&mut self, text: String, plain: bool, at: Location) -> Result<(), YamlError> {
        self.count(at)?;
        if let Some(Frame::Map {
            location,
            entries,
            key,
            index,
            pending,
        }) = self.stack.last_mut()
            && key.is_none()
        {
            if entries.is_empty() && at < *location {
                *location = at;
            }
            if let Some(error) = pending.take() {
                return Err(error.relocate(*location));
            }
            check_key(&text, plain, at)?;
            match index.entry(text.clone()) {
                Slot::Occupied(first) => {
                    let first = entries.get(*first.get()).map_or(at, |e| e.key_location);
                    return Err(YamlError::new(
                        YamlErrorKind::DuplicateKey,
                        format!("duplicate key `{text}`; it is first used at {first}"),
                    )
                    .at(at));
                }
                Slot::Vacant(slot) => {
                    slot.insert(entries.len());
                }
            }
            *key = Some((text, at));
            return Ok(());
        }
        let value = if plain {
            resolve_plain(&text).map_err(|e| e.at(at))?
        } else {
            Value::Str(text)
        };
        self.attach(Node {
            value,
            location: at,
        })
    }

    fn open(&mut self, map: bool, at: Location) -> Result<(), YamlError> {
        self.count(at)?;
        if let Some(Frame::Map { key: None, .. }) = self.stack.last() {
            return Err(YamlError::new(
                YamlErrorKind::Mismatch,
                "mapping keys must be text, not a sequence or a map",
            )
            .at(at));
        }
        if self.stack.len() >= self.limits.max_depth {
            return Err(YamlError::new(
                YamlErrorKind::LimitExceeded,
                format!(
                    "the document is nested more than {} levels deep",
                    self.limits.max_depth
                ),
            )
            .at(at));
        }
        self.stack.push(if map {
            Frame::Map {
                location: at,
                entries: Vec::new(),
                key: None,
                index: HashMap::new(),
                pending: None,
            }
        } else {
            Frame::Seq {
                location: at,
                items: Vec::new(),
            }
        });
        Ok(())
    }

    fn close(&mut self) -> Result<(), YamlError> {
        let node = match self.stack.pop() {
            Some(Frame::Seq { location, items }) => Node {
                value: Value::Seq(items),
                location,
            },
            Some(Frame::Map {
                pending: Some(error),
                location,
                ..
            }) => return Err(error.relocate(location)),
            Some(Frame::Map {
                location,
                entries,
                index,
                key: None,
                ..
            }) => Node {
                value: Value::Map(Map { entries, index }),
                location,
            },
            // A key with no value, or an end with nothing open.
            Some(Frame::Map { location, .. }) => return Err(internal(location)),
            None => return Err(internal(Location { line: 1, column: 1 })),
        };
        self.attach(node)
    }

    fn attach(&mut self, node: Node) -> Result<(), YamlError> {
        match self.stack.last_mut() {
            None => self.roots.push(node),
            Some(Frame::Seq { items, .. }) => items.push(node),
            Some(Frame::Map { entries, key, .. }) => match key.take() {
                Some((key, key_location)) => entries.push(Entry {
                    key,
                    key_location,
                    value: node,
                }),
                None => return Err(internal(node.location)),
            },
        }
        Ok(())
    }
}

/// An event sequence the parser should never produce.
fn internal(at: Location) -> YamlError {
    YamlError::new(
        YamlErrorKind::Syntax,
        "unexpected event sequence from the YAML parser",
    )
    .at(at)
}

/// Keys are text. A plain key must also read as text under the typing rules
/// below, and `<<` (the YAML 1.1 merge key) is refused.
fn check_key(text: &str, plain: bool, at: Location) -> Result<(), YamlError> {
    if !plain {
        return Ok(());
    }
    if text == "<<" {
        return Err(YamlError::new(
            YamlErrorKind::UnsupportedFeature,
            "merge keys (`<<`) are not supported",
        )
        .at(at));
    }
    match resolve_plain(text) {
        Ok(Value::Str(_)) => Ok(()),
        Ok(_) => Err(YamlError::new(
            YamlErrorKind::Mismatch,
            format!("mapping keys must be text; quote `{text}` to use it as a key"),
        )
        .at(at)),
        Err(e) => Err(e.at(at)),
    }
}

/// Types a plain (unquoted) scalar.
///
/// - `null`, `Null`, `NULL`, `~` and the empty scalar are null, and
///   `true`/`false` (also capitalised or upper case) are booleans, as in
///   both YAML 1.1 and the YAML 1.2 core schema.
/// - Numbers must use JSON syntax, and are integers if they have no
///   fraction or exponent.
/// - A scalar that some YAML readers type differently from others is an
///   error: the YAML 1.1 booleans (`yes`, `no`, `on`, `off`, `y`, `n`; the
///   "Norway problem"), and numbers that are not JSON numbers (`010`, `+1`,
///   `0x1f`, `0o17`, `1_000`, `1:30`, `.5`, `1.`, `.inf`, `.nan`).
/// - Everything else is text.
pub(crate) fn resolve_plain(text: &str) -> Result<Value, YamlError> {
    match text {
        "" | "~" | "null" | "Null" | "NULL" => return Ok(Value::Null),
        "true" | "True" | "TRUE" => return Ok(Value::Bool(true)),
        "false" | "False" | "FALSE" => return Ok(Value::Bool(false)),
        "y" | "Y" | "yes" | "Yes" | "YES" | "n" | "N" | "no" | "No" | "NO" | "on" | "On" | "ON"
        | "off" | "Off" | "OFF" => {
            return Err(YamlError::new(
                YamlErrorKind::AmbiguousScalar,
                format!(
                    "`{text}` is a boolean in YAML 1.1 but text in YAML 1.2; quote it (\"{text}\") for text, or write true or false"
                ),
            ));
        }
        _ => {}
    }
    if let Some(number) = json_number(text) {
        return number;
    }
    if is_number_like(text) {
        return Err(YamlError::new(
            YamlErrorKind::AmbiguousScalar,
            format!(
                "`{text}` is read as a number by some YAML readers and as text by others; quote it for text, or write a decimal number"
            ),
        ));
    }
    Ok(Value::Str(text.to_owned()))
}

/// Reads `text` if it is a JSON number (RFC 8259 section 6).
fn json_number(text: &str) -> Option<Result<Value, YamlError>> {
    // Always `Ok` today; the `Result` keeps one shape for every scalar rule.
    let bytes = text.as_bytes();
    let mut i = usize::from(bytes.first() == Some(&b'-'));
    let digits = |i: &mut usize| {
        let start = *i;
        while bytes.get(*i).is_some_and(u8::is_ascii_digit) {
            *i += 1;
        }
        *i - start
    };
    let int_start = i;
    let int_len = digits(&mut i);
    if int_len == 0 || (int_len > 1 && bytes.get(int_start) == Some(&b'0')) {
        return None;
    }
    let mut integer = true;
    if bytes.get(i) == Some(&b'.') {
        i += 1;
        if digits(&mut i) == 0 {
            return None;
        }
        integer = false;
    }
    if matches!(bytes.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(bytes.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        if digits(&mut i) == 0 {
            return None;
        }
        integer = false;
    }
    if i != bytes.len() {
        return None;
    }
    let out_of_range = || Value::OutOfRange(text.to_owned());
    Some(Ok(if text == "-0" {
        // serde_json reads `-0` as the float -0.0, which integer fields reject.
        Value::Float(-0.0)
    } else if integer {
        if text.starts_with('-') {
            text.parse().map_or_else(|_| out_of_range(), Value::NegInt)
        } else {
            text.parse().map_or_else(|_| out_of_range(), Value::UInt)
        }
    } else {
        match text.parse::<f64>() {
            Ok(f) if f.is_finite() => Value::Float(f),
            _ => out_of_range(),
        }
    }))
}

/// Whether a plain scalar that is not a JSON number is still read as a
/// number by YAML 1.1 or by the YAML 1.2 core schema.
fn is_number_like(text: &str) -> bool {
    let rest = text.strip_prefix(['-', '+']).unwrap_or(text);
    if matches!(rest, ".inf" | ".Inf" | ".INF" | ".nan" | ".NaN" | ".NAN") {
        return true;
    }
    // Some readers also accept upper-case radix prefixes.
    for (prefix, radix) in [("0x", 16), ("0o", 8), ("0b", 2)] {
        let digits = rest
            .get(..2)
            .filter(|p| p.eq_ignore_ascii_case(prefix))
            .and_then(|_| rest.get(2..));
        if let Some(digits) = digits
            && !digits.is_empty()
            && digits.chars().all(|c| c == '_' || c.is_digit(radix))
        {
            return true;
        }
    }
    is_sexagesimal(rest) || is_decimal_like(rest)
}

/// YAML 1.1 base-60 numbers, after the sign: the integer form
/// `[1-9][0-9_]*(:[0-5]?[0-9])+` (`1:30`, `190:20:30`) and the float form
/// `[0-9][0-9_]*(:[0-5]?[0-9])+\.[0-9_]*` (`1:30.5`). Anything else with a
/// colon, such as `1:60` or `0:30`, is text in YAML 1.1 and 1.2 alike.
fn is_sexagesimal(s: &str) -> bool {
    let (whole, fraction) = match s.split_once('.') {
        Some((whole, fraction)) => (whole, Some(fraction)),
        None => (s, None),
    };
    let mut parts = whole.split(':');
    let first = parts.next().unwrap_or("");
    let first_ok = first.bytes().next().is_some_and(|b| b.is_ascii_digit())
        && first.bytes().all(|b| b.is_ascii_digit() || b == b'_');
    let mut sexagesimal_parts = 0usize;
    let rest_ok = parts.all(|part| {
        sexagesimal_parts += 1;
        match part.as_bytes() {
            [d] => d.is_ascii_digit(),
            [tens, units] => (b'0'..=b'5').contains(tens) && units.is_ascii_digit(),
            _ => false,
        }
    });
    if !(first_ok && rest_ok && sexagesimal_parts > 0) {
        return false;
    }
    match fraction {
        None => !first.starts_with('0'),
        Some(fraction) => fraction.bytes().all(|b| b.is_ascii_digit() || b == b'_'),
    }
}

/// Decimal integers and floats in their YAML 1.1 and 1.2 forms: digits with
/// optional underscores, a fraction that may be empty, and an exponent.
/// Dotted versions such as `1.0.0` are not numbers.
fn is_decimal_like(s: &str) -> bool {
    let b = s.as_bytes();
    let mut i = 0;
    let run = |i: &mut usize, allow_underscore: bool| {
        let start = *i;
        while b
            .get(*i)
            .is_some_and(|c| c.is_ascii_digit() || (allow_underscore && *c == b'_'))
        {
            *i += 1;
        }
        *i - start
    };
    let has_int = run(&mut i, true) > 0;
    if has_int && !b.first().is_some_and(u8::is_ascii_digit) {
        return false;
    }
    if b.get(i) == Some(&b'.') {
        i += 1;
        let has_frac = run(&mut i, true) > 0;
        if !has_int && !has_frac {
            return false;
        }
    } else if !has_int {
        return false;
    }
    if matches!(b.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(b.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        if run(&mut i, false) == 0 {
            return false;
        }
    }
    i == b.len()
}
