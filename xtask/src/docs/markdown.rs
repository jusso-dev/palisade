//! The small amount of Markdown structure the docs build needs: code fences,
//! link destinations, headings and images. It is line based and follows
//! CommonMark closely enough for the repository's own documents, which the
//! unit tests and `cargo xtask docs check` exercise.

/// One line of a document, and whether it is inside a code fence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line<'a> {
    /// Prose (anything outside a fence).
    Text(&'a str),
    /// A fence opener, with its info string (`yaml policy`, `rust`, ...).
    Open { line: &'a str, info: &'a str },
    /// A line inside a fence.
    Code(&'a str),
    /// A fence closer.
    Close(&'a str),
}

/// `(char, length, info)` if `line` opens a fence: three or more backticks
/// or tildes after optional indentation. A backtick fence's info string may
/// not contain a backtick.
fn fence(line: &str) -> Option<(u8, usize, &str)> {
    let rest = line.trim_start();
    let c = *rest.as_bytes().first()?;
    if c != b'`' && c != b'~' {
        return None;
    }
    let n = rest.bytes().take_while(|&b| b == c).count();
    if n < 3 {
        return None;
    }
    let info = rest[n..].trim();
    if c == b'`' && info.contains('`') {
        return None;
    }
    Some((c, n, info))
}

/// Splits `source` into lines, marking fences. An unclosed fence runs to
/// the end of the document, as in CommonMark.
pub fn lines(source: &str) -> Vec<Line<'_>> {
    let mut out = Vec::new();
    let mut open: Option<(u8, usize)> = None;
    for line in source.split('\n') {
        match open {
            None => match fence(line) {
                Some((c, n, info)) => {
                    open = Some((c, n));
                    out.push(Line::Open { line, info });
                }
                None => out.push(Line::Text(line)),
            },
            Some((c, n)) => {
                let rest = line.trim();
                let closes = rest.len() >= n && rest.bytes().all(|b| b == c);
                if closes {
                    open = None;
                    out.push(Line::Close(line));
                } else {
                    out.push(Line::Code(line));
                }
            }
        }
    }
    out
}

/// Joins [`lines`] output back into a document.
pub fn join(lines: &[String]) -> String {
    lines.join("\n")
}

/// The byte ranges of code spans in one line of prose: a run of `n`
/// backticks up to the next run of exactly `n`. An unmatched run is text.
pub fn code_spans(line: &str) -> Vec<(usize, usize)> {
    let bytes = line.as_bytes();
    let mut spans = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'`' {
            i += 1;
            continue;
        }
        let n = bytes[i..].iter().take_while(|&&b| b == b'`').count();
        let mut j = i + n;
        let mut closed = None;
        while j < bytes.len() {
            if bytes[j] == b'`' {
                let m = bytes[j..].iter().take_while(|&&b| b == b'`').count();
                if m == n {
                    closed = Some(j + m);
                    break;
                }
                j += m;
            } else {
                j += 1;
            }
        }
        match closed {
            Some(end) => {
                spans.push((i, end));
                i = end;
            }
            None => i += n,
        }
    }
    spans
}

/// Rewrites every link destination in one line of prose with `f`:
/// inline links and images (`[text](dest "title")`, `<dest>` too) and
/// reference definitions (`[label]: dest`). Code spans are left alone. `f`
/// returns the new destination, or `None` to keep it.
pub fn rewrite_links(
    line: &str,
    f: &mut dyn FnMut(&str) -> Result<Option<String>, String>,
) -> Result<String, String> {
    // A reference definition: `[label]: dest`, indented at most 3 spaces.
    let indent = line.len() - line.trim_start_matches(' ').len();
    if indent <= 3 {
        let rest = &line[indent..];
        if let Some(close) = rest.strip_prefix('[').and_then(|r| r.find("]:")) {
            let after = &rest[close + 3..];
            let gap = after.len() - after.trim_start().len();
            let dest_start = indent + close + 3 + gap;
            let dest: &str = line[dest_start..]
                .split(char::is_whitespace)
                .next()
                .unwrap_or("");
            // `close` indexes the text after `[`, so the label is
            // `rest[1..1 + close]`; an empty label is not a definition.
            if close > 0 && !dest.is_empty() && !rest[1..1 + close].contains(']') {
                if let Some(new) = f(dest)? {
                    return Ok(format!(
                        "{}{new}{}",
                        &line[..dest_start],
                        &line[dest_start + dest.len()..]
                    ));
                }
                return Ok(line.to_owned());
            }
        }
    }
    let spans = code_spans(line);
    let in_code = |i: usize| spans.iter().any(|&(s, e)| s <= i && i < e);
    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut copied = 0;
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] != b']' || bytes[i + 1] != b'(' || in_code(i) {
            i += 1;
            continue;
        }
        let start = i + 2;
        let (dest_start, dest_end) = if bytes.get(start) == Some(&b'<') {
            match line[start..].find('>') {
                Some(end) => (start + 1, start + end),
                None => {
                    i += 1;
                    continue;
                }
            }
        } else {
            let mut depth = 0usize;
            let mut end = start;
            while end < bytes.len() {
                match bytes[end] {
                    b'(' => depth += 1,
                    b')' if depth == 0 => break,
                    b')' => depth -= 1,
                    b if b.is_ascii_whitespace() => break,
                    _ => {}
                }
                end += 1;
            }
            (start, end)
        };
        let dest = &line[dest_start..dest_end];
        if !dest.is_empty() {
            if let Some(new) = f(dest)? {
                out.push_str(&line[copied..dest_start]);
                out.push_str(&new);
                copied = dest_end;
            }
        }
        i = dest_end.max(i + 1);
    }
    out.push_str(&line[copied..]);
    Ok(out)
}

/// The ATX headings of a document outside fences, as `(line number, level,
/// text)`.
pub fn headings(source: &str) -> Vec<(usize, usize, String)> {
    let mut out = Vec::new();
    for (index, line) in lines(source).iter().enumerate() {
        let Line::Text(text) = line else { continue };
        let trimmed = text.trim_start_matches(' ');
        if text.len() - trimmed.len() > 3 {
            continue;
        }
        let level = trimmed.bytes().take_while(|&b| b == b'#').count();
        if !(1..=6).contains(&level) {
            continue;
        }
        let rest = &trimmed[level..];
        if rest.is_empty() || rest.starts_with(' ') || rest.starts_with('\t') {
            out.push((
                index + 1,
                level,
                rest.trim().trim_end_matches('#').trim().to_owned(),
            ));
        }
    }
    out
}

/// Accessibility problems in one document: the first heading must be the
/// only level-1 heading, levels may not skip (`##` to `####`), and every
/// image needs alt text.
pub fn accessibility(path: &str, source: &str) -> Vec<String> {
    let mut v = Vec::new();
    let headings = headings(source);
    match headings.first() {
        None => v.push(format!("{path}: has no heading; start with one `# Title`")),
        Some((line, level, _)) if *level != 1 => v.push(format!(
            "{path}:{line}: the first heading must be level 1 (`# Title`)"
        )),
        Some(_) => {}
    }
    for (line, _, text) in headings.iter().skip(1).filter(|h| h.1 == 1) {
        v.push(format!(
            "{path}:{line}: a second level-1 heading (`# {text}`); a page has one title"
        ));
    }
    for pair in headings.windows(2) {
        let ((_, a, _), (line, b, text)) = (&pair[0], &pair[1]);
        if *b > a + 1 {
            v.push(format!(
                "{path}:{line}: heading `{text}` skips from level {a} to {b}"
            ));
        }
    }
    for (index, line) in lines(source).iter().enumerate() {
        let Line::Text(text) = line else { continue };
        let spans = code_spans(text);
        let in_code = |i: usize| spans.iter().any(|&(s, e)| s <= i && i < e);
        for (i, _) in text.match_indices("![](") {
            if !in_code(i) {
                v.push(format!("{path}:{}: an image without alt text", index + 1));
            }
        }
        for (i, _) in text.match_indices("<img") {
            let tag_end = text[i..].find('>').map_or(text.len(), |e| i + e);
            if !in_code(i) && !text[i..tag_end].contains("alt=") {
                v.push(format!("{path}:{}: an `<img>` without `alt`", index + 1));
            }
        }
    }
    v
}

/// The fenced blocks of a document, as `(line number of the opener, info
/// string, body)`.
pub fn fenced_blocks(source: &str) -> Vec<(usize, String, String)> {
    let mut out = Vec::new();
    let mut current: Option<(usize, String, Vec<&str>)> = None;
    for (index, line) in lines(source).into_iter().enumerate() {
        match line {
            Line::Open { info, .. } => current = Some((index + 1, info.to_owned(), Vec::new())),
            Line::Code(text) => {
                if let Some((_, _, body)) = &mut current {
                    body.push(text);
                }
            }
            Line::Close(_) => {
                if let Some((at, info, body)) = current.take() {
                    out.push((at, info, body.join("\n")));
                }
            }
            Line::Text(_) => {}
        }
    }
    if let Some((at, info, body)) = current {
        out.push((at, info, body.join("\n")));
    }
    out
}

/// Escapes `<` and `>` outside code spans, line by line, so text taken from
/// a schema description (`one <kind>`) is not read as an HTML tag. Inside a
/// code span they are already literal.
pub fn prose(text: &str) -> String {
    let lines: Vec<String> = text
        .split('\n')
        .map(|line| {
            let spans = code_spans(line);
            let mut out = String::with_capacity(line.len());
            for (i, c) in line.char_indices() {
                let in_code = spans.iter().any(|&(s, e)| s <= i && i < e);
                match c {
                    '<' if !in_code => out.push_str("&lt;"),
                    '>' if !in_code => out.push_str("&gt;"),
                    c => out.push(c),
                }
            }
            out
        })
        .collect();
    lines.join("\n")
}

/// Escapes text for one cell of a Markdown table: one line, `|` escaped
/// (also inside code spans, as tables require), and [`prose`].
pub fn cell(text: &str) -> String {
    prose(&text.split_whitespace().collect::<Vec<_>>().join(" ")).replace('|', "\\|")
}

/// `text` as a code span, with enough backticks that any inside it stay
/// literal.
pub fn code(text: &str) -> String {
    let run = text.split(|c| c != '`').map(str::len).max().unwrap_or(0);
    if run == 0 {
        format!("`{text}`")
    } else {
        let fence = "`".repeat(run + 1);
        format!("{fence} {text} {fence}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rewrite_all(line: &str) -> String {
        rewrite_links(line, &mut |d| Ok(Some(format!("<{d}>")))).unwrap()
    }

    #[test]
    fn fences_open_and_close_with_the_same_character_and_length() {
        let doc = "a\n```yaml policy\nx\n~~~\n```\nb\n  ````\n```\n  ````\nc";
        let kinds: Vec<&str> = lines(doc)
            .iter()
            .map(|l| match l {
                Line::Text(_) => "T",
                Line::Open { .. } => "O",
                Line::Code(_) => "C",
                Line::Close(_) => "X",
            })
            .collect();
        assert_eq!(kinds, ["T", "O", "C", "C", "X", "T", "O", "C", "X", "T"]);
        let blocks = fenced_blocks(doc);
        assert_eq!(
            blocks[0],
            (2, "yaml policy".to_owned(), "x\n~~~".to_owned())
        );
        assert_eq!(blocks[1], (7, String::new(), "```".to_owned()));
        assert!(fence("``").is_none());
        assert!(fence("``` a`b").is_none());
    }

    #[test]
    fn link_destinations_are_rewritten_outside_code_spans() {
        assert_eq!(
            rewrite_all("see [a](x.md) and [b](y.md#z \"t\")"),
            "see [a](<x.md>) and [b](<y.md#z> \"t\")"
        );
        assert_eq!(rewrite_all("![alt](img.png)"), "![alt](<img.png>)");
        assert_eq!(
            rewrite_all("`[a](x.md)` [b](y.md)"),
            "`[a](x.md)` [b](<y.md>)"
        );
        assert_eq!(rewrite_all("``a`[b](c)`` d"), "``a`[b](c)`` d");
        assert_eq!(
            rewrite_all("[a](<with space.md>)"),
            "[a](<<with space.md>>)"
        );
        assert_eq!(rewrite_all("[a](f(1).md) x"), "[a](<f(1).md>) x");
        assert_eq!(
            rewrite_all("[label]: target.md \"t\""),
            "[label]: <target.md> \"t\""
        );
        assert_eq!(rewrite_all("   [label]: t.md"), "   [label]: <t.md>");
        assert_eq!(rewrite_all("    [label]: t.md"), "    [label]: t.md");
        assert_eq!(rewrite_all("no links ] ( here"), "no links ] ( here");
        assert_eq!(rewrite_all("[empty]()"), "[empty]()");
        assert_eq!(rewrite_all("[]: foo.md"), "[]: foo.md");
        assert_eq!(rewrite_all("[a]: x.md"), "[a]: <x.md>");
        let mut seen = Vec::new();
        rewrite_links("[a](one) [b](two)", &mut |d| {
            seen.push(d.to_owned());
            Ok(None)
        })
        .unwrap();
        assert_eq!(seen, ["one", "two"]);
        assert!(rewrite_links("[a](x)", &mut |_| Err("bad".to_owned())).is_err());
    }

    #[test]
    fn headings_skip_fences() {
        let doc = "# Title\n```\n# not\n```\n## A ##\n#nope\n    # indented code\n### B";
        let h: Vec<(usize, usize, String)> = headings(doc);
        assert_eq!(
            h,
            [
                (1, 1, "Title".to_owned()),
                (5, 2, "A".to_owned()),
                (8, 3, "B".to_owned())
            ]
        );
    }

    #[test]
    fn accessibility_rules() {
        assert!(accessibility("p", "# T\n## A\n### B\n## C\n![a diagram](x.svg)").is_empty());
        let v = accessibility("p", "## T\n# U\n#### V\n![](x.png)\n<img src=x>\n`![](ok)`");
        assert_eq!(v.len(), 5, "{v:#?}");
        assert!(v[0].contains("first heading must be level 1"));
        assert!(v[1].contains("second level-1 heading"));
        assert!(v[2].contains("skips from level 1 to 4"));
        assert!(v[3].contains("p:4: an image without alt text"));
        assert!(v[4].contains("p:5: an `<img>` without `alt`"));
        assert_eq!(accessibility("p", "text").len(), 1);
    }

    #[test]
    fn cells_and_code_spans() {
        assert_eq!(cell("a |b\n  <kind>"), "a \\|b &lt;kind&gt;");
        assert_eq!(cell("`<a|b>` <c>"), "`<a\\|b>` &lt;c&gt;");
        assert_eq!(prose("x <y>\n`<z>`"), "x &lt;y&gt;\n`<z>`");
        assert_eq!(code("^a$"), "`^a$`");
        assert_eq!(code("a`b"), "`` a`b ``");
    }
}
