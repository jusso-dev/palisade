//! Index anchors of single criteria (#42).
//!
//! An anchor is a set of keys with one guarantee: if the criterion is
//! `Match` for an object, then the object's facts contain at least one of
//! the keys. The rule index ([`crate::evaluate`]) files each rule under the
//! keys of its anchor, and a probe with the object's facts then finds every
//! rule that could match without evaluating the others.
//!
//! Keys are computed from the criterion's values with the same
//! normalisation that [`CompiledCriterion::compile`](super::CompiledCriterion::compile)
//! applies, and probes apply the same normalisation to the facts, so the
//! guarantee follows from how each operator matches:
//!
//! - Hashes (`equals`): the fact equals a value as hex digits in either
//!   case, so its decoded bytes equal the value's decoded bytes.
//! - Text (`equals` on version-resource strings, signer names, file names
//!   and extensions): the folded fact equals a folded value. Both sides are
//!   NFC-normalised before folding, and a case-sensitive comparison of NFC
//!   strings that succeeds also succeeds after the simple upper-case
//!   mapping, so keys and probes are always case-folded ([`fold`] with
//!   `case_sensitive` off).
//! - Paths (`equals`, `starts_with`, `wildcard` on `path.full` and
//!   `path.directory`): the folded fact starts with the value's literal
//!   part. For a wildcard that is the text before its first `*`, `?` or
//!   `[`. The key is that literal cut back to its last `\`, without the
//!   `\`, so a probe only has to look at the fact's prefixes that end at a
//!   separator. A value that starts with a path variable cannot match
//!   unless the variable has a value, so it is filed under the variable.
//! - SIDs and principals (`equals` on `user.sid` and `user.primary_group`,
//!   `member_of` on `user.groups` and `device.groups`): the canonical fact,
//!   or a canonical member of the fact, equals a canonical value.
//!
//! Every other criterion has no anchor: negative operators, regular
//! expressions, `contains`, `ends_with`, versions, yes-or-no facts and the
//! other context facts.

use crate::context::{normalize_principal, normalize_sid};
use crate::facts::PathVariable;
use crate::model::{Criterion, Field, FieldClass, Operator};

use super::{fold, normalize_hex, path_value};

/// The keys of one criterion's anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LeafAnchor {
    /// Decoded digests of a hash field, all of the field's length.
    Hash(Field, Vec<Vec<u8>>),
    /// Decoded SHA-256 leaf certificate thumbprints.
    Thumbprint(Vec<[u8; 32]>),
    /// Folded text of a text or file-name field, including the signer
    /// publisher and issuer.
    Text(Field, Vec<String>),
    /// Path prefixes and path variables of `path.full` or
    /// `path.directory`.
    Path {
        /// `path.full` or `path.directory`.
        field: Field,
        /// Folded literal prefixes, each ending before a `\` of the fact
        /// or at its end. Never empty strings.
        prefixes: Vec<String>,
        /// The variables that values start with.
        variables: Vec<PathVariable>,
    },
    /// Canonical SIDs or object IDs of a principal field.
    Principal(Field, Vec<String>),
}

impl LeafAnchor {
    /// Which anchor of an `all` the rule is filed under, lowest first: the
    /// one whose fact is cheapest to compute ([`crate::demand::FactSet::round`]),
    /// then the most selective. A rule is then a candidate as soon as its
    /// cheap facts allow it, and its expensive facts are only asked for if
    /// the cheap part of its tree did not already rule it out.
    pub(crate) fn rank(&self) -> (usize, u8) {
        (
            crate::demand::FactSet::of_field(self.field()).round(),
            self.selectivity(),
        )
    }

    /// How selective the anchor is, lowest first.
    const fn selectivity(&self) -> u8 {
        match self {
            Self::Hash(..) => 0,
            Self::Thumbprint(_) => 1,
            Self::Text(field, _) => match field {
                Field::SignerPublisher => 2,
                _ => 3,
            },
            Self::Principal(..) => 4,
            Self::Path { .. } => 5,
        }
    }

    /// The field the anchor reads.
    pub(crate) const fn field(&self) -> Field {
        match self {
            Self::Hash(field, _)
            | Self::Text(field, _)
            | Self::Path { field, .. }
            | Self::Principal(field, _) => *field,
            Self::Thumbprint(_) => Field::SignerLeafThumbprint,
        }
    }
}

/// The anchor of a criterion, if it has one. The criterion must compile;
/// for one that does not, the result is `None`.
pub(crate) fn leaf_anchor(c: &Criterion) -> Option<LeafAnchor> {
    if !c.operator.is_positive() || !c.operator.applies_to(c.field.class()) {
        return None;
    }
    let field = c.field;
    match (field.class(), c.operator) {
        (FieldClass::Hash { hex_len }, Operator::Equals) => {
            let digests = c
                .values
                .iter()
                .map(|v| {
                    normalize_hex(v)
                        .filter(|h| h.len() == hex_len)
                        .and_then(|h| decode_hex(&h))
                })
                .collect::<Option<Vec<Vec<u8>>>>()?;
            if field == Field::SignerLeafThumbprint {
                let thumbprints = digests
                    .into_iter()
                    .map(|d| <[u8; 32]>::try_from(d.as_slice()).ok())
                    .collect::<Option<Vec<_>>>()?;
                Some(LeafAnchor::Thumbprint(thumbprints))
            } else {
                Some(LeafAnchor::Hash(field, digests))
            }
        }
        (FieldClass::Text | FieldClass::FileName, Operator::Equals) if is_text_field(field) => {
            Some(LeafAnchor::Text(
                field,
                c.values.iter().map(|v| fold(v, false)).collect(),
            ))
        }
        (FieldClass::Path, Operator::Equals | Operator::StartsWith | Operator::Wildcard) => {
            let wildcard = c.operator == Operator::Wildcard;
            let mut prefixes = Vec::new();
            let mut variables = Vec::new();
            for v in &c.values {
                let (variable, text, _) = path_value(v, wildcard).ok()?;
                if let Some(variable) = variable {
                    variables.push(variable);
                    continue;
                }
                let folded = fold(&text, false);
                let literal = if wildcard {
                    match folded.find(['*', '?', '[']) {
                        // Only the components before the one that holds
                        // the first wildcard are fixed.
                        Some(end) => folded[..end].rfind('\\').map(|cut| &folded[..cut])?,
                        None => trim_separator(&folded),
                    }
                } else {
                    trim_separator(&folded)
                };
                if literal.is_empty() {
                    return None;
                }
                prefixes.push(literal.to_owned());
            }
            variables.sort();
            variables.dedup();
            Some(LeafAnchor::Path {
                field,
                prefixes,
                variables,
            })
        }
        (FieldClass::Sid, Operator::Equals) => Some(LeafAnchor::Principal(
            field,
            c.values
                .iter()
                .map(|v| normalize_sid(v))
                .collect::<Option<_>>()?,
        )),
        (FieldClass::PrincipalSet, Operator::MemberOf) => Some(LeafAnchor::Principal(
            field,
            c.values
                .iter()
                .map(|v| normalize_principal(v))
                .collect::<Option<_>>()?,
        )),
        _ => None,
    }
}

/// The text fields with an index: version-resource strings, the signer's
/// names, and the file name and extension.
const fn is_text_field(field: Field) -> bool {
    matches!(
        field,
        Field::MetaOriginalFilename
            | Field::MetaInternalName
            | Field::MetaFileDescription
            | Field::MetaProductName
            | Field::MetaCompanyName
            | Field::SignerPublisher
            | Field::SignerIssuer
            | Field::PathFileName
            | Field::PathExtension
    )
}

/// `s` without one trailing `\`.
fn trim_separator(s: &str) -> &str {
    s.strip_suffix('\\').unwrap_or(s)
}

/// The bytes of an even number of hex digits in either case.
pub(crate) fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    let mut out = vec![0u8; hex.len() / 2];
    decode_hex_into(hex, &mut out).map(|()| out)
}

/// Decodes `hex` into `out`, which must be exactly half its length. Does
/// not allocate.
pub(crate) fn decode_hex_into(hex: &str, out: &mut [u8]) -> Option<()> {
    let digits = hex.as_bytes();
    if digits.len() != out.len() * 2 {
        return None;
    }
    for (byte, pair) in out.iter_mut().zip(digits.chunks_exact(2)) {
        *byte = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(())
}

const fn nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// The prefixes of a folded path fact that a probe looks up: the text
/// before each `\`, and the whole text without a trailing `\`. Does not
/// allocate.
pub(crate) fn probe_prefixes(fact: &str) -> impl Iterator<Item = &str> {
    fact.match_indices('\\')
        .map(move |(i, _)| &fact[..i])
        .chain(core::iter::once(trim_separator(fact)))
        .filter(|p| !p.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn crit(field: Field, operator: Operator, values: &[&str]) -> Criterion {
        Criterion::new(field, operator, values.iter().copied())
    }

    fn prefixes(anchor: Option<LeafAnchor>) -> Vec<String> {
        match anchor {
            Some(LeafAnchor::Path { prefixes, .. }) => prefixes,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn hashes_are_decoded() {
        let a = leaf_anchor(&crit(
            Field::HashSha256,
            Operator::Equals,
            &[&"AB".repeat(32)],
        ));
        assert_eq!(
            a,
            Some(LeafAnchor::Hash(Field::HashSha256, vec![vec![0xab; 32]]))
        );
        let a = leaf_anchor(&crit(
            Field::SignerLeafThumbprint,
            Operator::Equals,
            &[&format!("0x{}", "01".repeat(32))],
        ));
        assert_eq!(a, Some(LeafAnchor::Thumbprint(vec![[1; 32]])));
        assert_eq!(
            leaf_anchor(&crit(
                Field::HashSha256,
                Operator::NotEquals,
                &[&"ab".repeat(32)]
            )),
            None
        );
    }

    #[test]
    fn path_prefixes() {
        let p = |op, v: &str| prefixes(leaf_anchor(&crit(Field::PathFull, op, &[v])));
        assert_eq!(p(Operator::Equals, r"C:\Tools\a.exe"), [r"C:\TOOLS\A.EXE"]);
        assert_eq!(p(Operator::StartsWith, r"c:\tools\"), [r"C:\TOOLS"]);
        assert_eq!(
            p(Operator::Wildcard, r"C:\Program Files\App*\x.exe"),
            [r"C:\PROGRAM FILES"]
        );
        assert_eq!(p(Operator::Wildcard, r"C:\a\b\*.exe"), [r"C:\A\B"]);
        assert_eq!(p(Operator::Wildcard, r"C:\a\b"), [r"C:\A\B"]);
        assert_eq!(p(Operator::Equals, r"C:\"), ["C:"]);
        // No fixed component: no anchor.
        assert_eq!(
            leaf_anchor(&crit(Field::PathFull, Operator::Wildcard, &[r"**\cmd.exe"])),
            None
        );
        assert_eq!(
            leaf_anchor(&crit(Field::PathFull, Operator::Wildcard, &[r"?:\x\y"])),
            None
        );
        assert_eq!(
            leaf_anchor(&crit(Field::PathFull, Operator::Wildcard, &[r"C*"])),
            None
        );
        // Variables are filed under the variable.
        let a = leaf_anchor(&crit(
            Field::PathDirectory,
            Operator::StartsWith,
            &[r"%PROGRAMFILES%\App"],
        ));
        assert_eq!(
            a,
            Some(LeafAnchor::Path {
                field: Field::PathDirectory,
                prefixes: vec![],
                variables: vec![PathVariable::ProgramFiles]
            })
        );
        // Negative and text operators have none.
        assert_eq!(
            leaf_anchor(&crit(Field::PathFull, Operator::EndsWith, &[r".exe"])),
            None
        );
        assert_eq!(
            leaf_anchor(&crit(Field::PathFull, Operator::NotEquals, &[r"C:\a"])),
            None
        );
    }

    #[test]
    fn text_and_principals() {
        let a = leaf_anchor(&crit(
            Field::SignerPublisher,
            Operator::Equals,
            &["Example Ltd"],
        ));
        assert_eq!(
            a,
            Some(LeafAnchor::Text(
                Field::SignerPublisher,
                vec!["EXAMPLE LTD".into()]
            ))
        );
        let mut cs = crit(Field::MetaProductName, Operator::Equals, &["Suite"]);
        cs.case_sensitive = Some(true);
        assert_eq!(
            leaf_anchor(&cs),
            Some(LeafAnchor::Text(
                Field::MetaProductName,
                vec!["SUITE".into()]
            ))
        );
        assert_eq!(
            leaf_anchor(&crit(Field::MetaProductName, Operator::Contains, &["S"])),
            None
        );
        assert_eq!(
            leaf_anchor(&crit(Field::MetaFileVersion, Operator::Equals, &["1.0"])),
            None
        );
        assert_eq!(
            leaf_anchor(&crit(Field::UserSid, Operator::Equals, &["s-1-5-032-544"])),
            Some(LeafAnchor::Principal(
                Field::UserSid,
                vec!["S-1-5-32-544".into()]
            ))
        );
        assert_eq!(
            leaf_anchor(&crit(
                Field::UserGroups,
                Operator::MemberOf,
                &["S-1-5-32-544"]
            ))
            .map(|a| a.field()),
            Some(Field::UserGroups)
        );
        assert_eq!(
            leaf_anchor(&crit(
                Field::UserGroups,
                Operator::NotMemberOf,
                &["S-1-5-32-544"]
            )),
            None
        );
        assert_eq!(
            leaf_anchor(&crit(Field::DeviceHostname, Operator::Equals, &["h"])),
            None
        );
    }

    #[test]
    fn probe_prefixes_end_at_separators() {
        let p: Vec<&str> = probe_prefixes(r"C:\A\B.EXE").collect();
        assert_eq!(p, ["C:", r"C:\A", r"C:\A\B.EXE"]);
        let p: Vec<&str> = probe_prefixes(r"C:\").collect();
        assert_eq!(p, ["C:", "C:"]);
        let p: Vec<&str> = probe_prefixes(r"\\SRV\SHARE\X").collect();
        assert_eq!(p, [r"\", r"\\SRV", r"\\SRV\SHARE", r"\\SRV\SHARE\X"]);
    }

    #[test]
    fn hex_decoding() {
        assert_eq!(decode_hex("00ffA0"), Some(vec![0, 0xff, 0xa0]));
        assert_eq!(decode_hex("0g"), None);
        let mut out = [0u8; 2];
        assert_eq!(decode_hex_into("abc", &mut out), None);
    }
}
