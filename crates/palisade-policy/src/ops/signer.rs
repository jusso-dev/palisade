//! Signer criteria (#31): which signatures take part, and how each is
//! tested.
//!
//! A signer criterion matches if any signature that takes part satisfies
//! both its field test and every constraint of its options. A signature
//! takes part when:
//!
//! - its status is accepted: by default `valid`, `valid_expired_timestamped`
//!   or `catalog_signed`, or the rule's `accept_status`. A
//!   `digest_mismatch` signature takes part only with
//!   `allow_digest_mismatch: true`, which validation always warns about;
//! - it comes from the chosen `source` (`embedded`, `catalog` or `any`);
//! - it is at the chosen `signature_index`, counted among the signatures
//!   of that source, if one is set.
//!
//! The constraints (`signed_after`, `countersigned`, `min_key_bits`,
//! `disallowed_algorithms`) are combined with the field test with Kleene
//! AND, per signature. A fact a test or constraint needs that is absent or
//! malformed makes that signature's result `Unknown` ([`Note::FactMissing`],
//! [`Note::FactMalformed`]), so it can never be what makes a criterion
//! match, and a negated signer test on it is `Unknown` too.
//!
//! - `signer.publisher` compares the leaf subject's common name, or with
//!   `component` its organisation (`o`) or whole distinguished name
//!   (`full_dn`).
//! - `signer.tbs_hash` compares the TBS hash of the leaf, the
//!   intermediates, the root, or any of them (`position`, default `any`).
//!   Digests are 40, 64, 96 or 128 hex digits, compared in either case.
//! - `signer.eku` holds the leaf's extended key usages as a set of OIDs,
//!   compared arc by arc, so `1.3.6.01` equals `1.3.6.1`.
//! - `signed_after` needs a trusted timestamp at or after the instant; the
//!   signer's own claimed signing time is never used. Timestamps are whole
//!   seconds, so a fractional instant is rounded up.
//! - `min_key_bits` needs every key of the chain to be at least that
//!   strong, in RSA-equivalent bits ([`KeyFact::rsa_equivalent_bits`]).

use super::{CompileErrorKind, CompiledCriterion, Note, Notes, Tri, Values};
use crate::facts::{
    DigestAlgorithm, KeyFact, SignatureSource, SignerDetails, SignerFact, SignerStatus,
};
use crate::model::{
    Criterion, Field, MAX_KEY_BITS, MAX_SIGNATURE_INDEX, SignerSource, SubjectComponent,
    TbsPosition,
};

/// The compiled `signer` options of a criterion: every default for a
/// criterion without them.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct SignerOpts {
    component: SubjectComponent,
    position: TbsPosition,
    /// The accepted statuses, one bit each in [`SignerStatus::ALL`] order;
    /// 0 for the default.
    accept: u8,
    allow_digest_mismatch: bool,
    source: SignerSource,
    index: Option<u8>,
    /// `signed_after`, in seconds since the Unix epoch.
    after: Option<i64>,
    countersigned: bool,
    min_key_bits: Option<u32>,
    /// The disallowed algorithms, one bit each in [`DigestAlgorithm::ALL`]
    /// order.
    disallowed: u8,
}

fn status_bit(s: SignerStatus) -> u8 {
    let i = SignerStatus::ALL.iter().position(|x| *x == s).unwrap_or(0);
    1 << i
}

fn algorithm_bit(a: DigestAlgorithm) -> u8 {
    let i = DigestAlgorithm::ALL
        .iter()
        .position(|x| *x == a)
        .unwrap_or(0);
    1 << i
}

impl SignerOpts {
    /// Whether a signature with this status takes part.
    fn accepts(&self, status: SignerStatus) -> bool {
        if status == SignerStatus::DigestMismatch {
            self.allow_digest_mismatch
        } else if self.accept == 0 {
            status.is_trusted()
        } else {
            self.accept & status_bit(status) != 0
        }
    }

    const fn includes(&self, source: SignatureSource) -> bool {
        matches!(
            (self.source, source),
            (SignerSource::Any, _)
                | (SignerSource::Embedded, SignatureSource::Embedded)
                | (SignerSource::Catalog, SignatureSource::Catalog)
        )
    }

    /// The constraints on one signature, with Kleene AND.
    fn constraints(&self, d: &SignerDetails, notes: &mut Notes) -> Tri {
        let mut r = Tri::Match;
        if let Some(after) = self.after {
            r = r.and(known(d.timestamp.map(|t| t >= after), notes));
        }
        if self.countersigned {
            r = r.and(known(d.countersigned, notes));
        }
        if let Some(min) = self.min_key_bits {
            r = r.and(match d.keys.as_deref() {
                Some(keys) if !keys.is_empty() => {
                    keys.iter()
                        .map(|k| key_test(*k, min))
                        .fold(Tri::Match, |acc, t| {
                            if t == Tri::Unknown {
                                notes.insert(Note::FactMalformed);
                            }
                            acc.and(t)
                        })
                }
                // A signature has at least the leaf's key.
                Some(_) => malformed(notes),
                None => missing(notes),
            });
        }
        if self.disallowed != 0 {
            r = r.and(match d.algorithms.as_deref() {
                Some(algs) if !algs.is_empty() => Tri::from_bool(
                    algs.iter()
                        .all(|a| self.disallowed & algorithm_bit(*a) == 0),
                ),
                Some(_) => malformed(notes),
                None => missing(notes),
            });
        }
        r
    }
}

fn key_test(key: KeyFact, min: u32) -> Tri {
    key.rsa_equivalent_bits()
        .map_or(Tri::Unknown, |bits| Tri::from_bool(bits >= min))
}

fn missing(notes: &mut Notes) -> Tri {
    notes.insert(Note::FactMissing);
    Tri::Unknown
}

fn malformed(notes: &mut Notes) -> Tri {
    notes.insert(Note::FactMalformed);
    Tri::Unknown
}

fn known(fact: Option<bool>, notes: &mut Notes) -> Tri {
    fact.map_or_else(|| missing(notes), Tri::from_bool)
}

/// Every problem with a criterion's `signer` options, each with the JSON
/// Pointer of the option below the criterion.
pub(crate) fn option_problems(c: &Criterion) -> Vec<(&'static str, CompileErrorKind)> {
    let Some(o) = c.signer.as_deref() else {
        return Vec::new();
    };
    if !c.field.is_signer() {
        return vec![(
            "signer",
            CompileErrorKind::OptionNotApplicable("signer", "`signer.*` fields"),
        )];
    }
    let invalid = |why: &str| CompileErrorKind::InvalidValue(why.to_owned());
    let mut out = Vec::new();
    if o.component.is_some() && c.field != Field::SignerPublisher {
        out.push((
            "signer/component",
            CompileErrorKind::OptionNotApplicable("signer.component", "`signer.publisher`"),
        ));
    }
    if o.position.is_some() && c.field != Field::SignerTbsHash {
        out.push((
            "signer/position",
            CompileErrorKind::OptionNotApplicable("signer.position", "`signer.tbs_hash`"),
        ));
    }
    match o.accept_status.as_deref() {
        Some([]) => out.push(("signer/accept_status", invalid("list at least one status"))),
        Some(list) if list.contains(&SignerStatus::DigestMismatch) => out.push((
            "signer/accept_status",
            invalid(
                "`digest_mismatch` cannot be accepted here: the file was changed after it was signed; set `allow_digest_mismatch: true` if the rule must match it anyway",
            ),
        )),
        _ => {}
    }
    if o.signature_index.is_some_and(|i| i > MAX_SIGNATURE_INDEX) {
        out.push((
            "signer/signature_index",
            CompileErrorKind::InvalidValue(format!("at most {MAX_SIGNATURE_INDEX}")),
        ));
    }
    if o.signed_after
        .as_deref()
        .is_some_and(|t| instant(t).is_none())
    {
        out.push((
            "signer/signed_after",
            invalid("expected an RFC 3339 time with an offset, such as `2024-01-01T00:00:00Z`"),
        ));
    }
    if o.min_key_bits.is_some_and(|b| b == 0 || b > MAX_KEY_BITS) {
        out.push((
            "signer/min_key_bits",
            CompileErrorKind::InvalidValue(format!("expected 1 to {MAX_KEY_BITS} bits")),
        ));
    }
    out
}

/// An RFC 3339 instant with an offset, in seconds since the Unix epoch,
/// rounded up to a whole second. Trusted timestamps are whole seconds, so
/// rounding up keeps `timestamp >= instant` false for every timestamp
/// before the instant: `00:00:00.500Z` rejects a signature at `00:00:00Z`.
fn instant(s: &str) -> Option<i64> {
    let t = s.parse::<jiff::Timestamp>().ok()?;
    let up = i64::from(t.subsec_nanosecond() > 0);
    Some(t.as_second().saturating_add(up))
}

/// Compiles the options of a criterion whose options passed
/// [`option_problems`].
pub(super) fn compile_options(c: &Criterion) -> SignerOpts {
    let Some(o) = c.signer.as_deref() else {
        return SignerOpts::default();
    };
    SignerOpts {
        component: o.component.unwrap_or_default(),
        position: o.position.unwrap_or_default(),
        accept: o
            .accept_status
            .iter()
            .flatten()
            .fold(0, |acc, s| acc | status_bit(*s)),
        allow_digest_mismatch: o.allow_digest_mismatch,
        source: o.source.unwrap_or_default(),
        index: o.signature_index,
        after: o.signed_after.as_deref().and_then(instant),
        countersigned: o.countersigned,
        min_key_bits: o.min_key_bits,
        disallowed: o
            .disallowed_algorithms
            .iter()
            .fold(0, |acc, a| acc | algorithm_bit(*a)),
    }
}

/// An object identifier in dotted form, with its arcs as written without
/// leading zeros: `1.3.6.01` is `1.3.6.1`. `None` if it is not one: at
/// least two arcs of decimal digits, the first 0, 1 or 2.
pub(super) fn canonical_oid(s: &str) -> Option<String> {
    let arcs: Vec<u64> = s
        .split('.')
        .map(|a| {
            if a.is_empty() || !a.bytes().all(|b| b.is_ascii_digit()) {
                None
            } else {
                a.parse().ok()
            }
        })
        .collect::<Option<_>>()?;
    if arcs.len() < 2 || arcs[0] > 2 {
        return None;
    }
    Some(
        arcs.iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join("."),
    )
}

/// Whether a digest fact is one a certificate's signature algorithm can
/// give: 40, 64, 96 or 128 hex digits.
fn is_digest(fact: &str) -> bool {
    matches!(fact.len(), 40 | 64 | 96 | 128) && fact.bytes().all(|b| b.is_ascii_hexdigit())
}

impl CompiledCriterion {
    pub(super) fn eval_signers(&self, signers: Option<&[SignerFact]>, notes: &mut Notes) -> Tri {
        let Some(signers) = signers else {
            return missing(notes);
        };
        let o = &self.signer;
        let mut result = Tri::NoMatch;
        let mut untrusted = false;
        // An index counts among the signatures of the chosen source.
        for (index, signer) in signers.iter().filter(|s| o.includes(s.source)).enumerate() {
            if o.index.is_some_and(|i| usize::from(i) != index) {
                continue;
            }
            if !o.accepts(signer.status) {
                untrusted = true;
                continue;
            }
            let test = self.signer_test(signer, notes);
            if test == Tri::NoMatch {
                continue;
            }
            result = result.or(test.and(o.constraints(&signer.details, notes)));
            if result == Tri::Match {
                break;
            }
        }
        if result == Tri::NoMatch && untrusted {
            notes.insert(Note::SignerNotTrusted);
        }
        result
    }

    /// The field test on one signature.
    fn signer_test(&self, s: &SignerFact, notes: &mut Notes) -> Tri {
        let d = &s.details;
        let fact = match self.field {
            Field::SignerPublisher => match self.signer.component {
                SubjectComponent::Cn => s.publisher.as_deref(),
                SubjectComponent::O => d.subject_organization.as_deref(),
                SubjectComponent::FullDn => d.subject_dn.as_deref(),
            },
            Field::SignerIssuer => s.issuer.as_deref(),
            Field::SignerLeafThumbprint => s.leaf_thumbprint_sha256.as_deref(),
            Field::SignerLeafThumbprintSha1 => d.leaf_thumbprint_sha1.as_deref(),
            Field::SignerPca => d.pca.as_deref(),
            Field::SignerRootThumbprint => d.root_thumbprint_sha256.as_deref(),
            Field::SignerRootThumbprintSha1 => d.root_thumbprint_sha1.as_deref(),
            Field::SignerTbsHash => return self.tbs_test(d, notes),
            Field::SignerEku => return self.eku_test(d, notes),
            _ => return malformed(notes),
        };
        match fact {
            Some(fact) => self.eval_value(fact, notes),
            None => missing(notes),
        }
    }

    fn tbs_test(&self, d: &SignerDetails, notes: &mut Notes) -> Tri {
        let Values::Text(want) = &self.values else {
            return malformed(notes);
        };
        let mut one = |fact: Option<&str>| match fact {
            Some(f) if is_digest(f) => {
                Tri::from_bool(want.iter().any(|w| f.eq_ignore_ascii_case(w)))
            }
            Some(_) => malformed(notes),
            None => missing(notes),
        };
        let leaf = |one: &mut dyn FnMut(Option<&str>) -> Tri| one(d.leaf_tbs_hash.as_deref());
        let root = |one: &mut dyn FnMut(Option<&str>) -> Tri| one(d.root_tbs_hash.as_deref());
        let intermediate =
            |one: &mut dyn FnMut(Option<&str>) -> Tri| match &d.intermediate_tbs_hashes {
                Some(list) => list
                    .iter()
                    .fold(Tri::NoMatch, |acc, h| acc.or(one(Some(h)))),
                None => one(None),
            };
        match self.signer.position {
            TbsPosition::Leaf => leaf(&mut one),
            TbsPosition::Root => root(&mut one),
            TbsPosition::Intermediate => intermediate(&mut one),
            TbsPosition::Any => leaf(&mut one).or(intermediate(&mut one)).or(root(&mut one)),
        }
    }

    fn eku_test(&self, d: &SignerDetails, notes: &mut Notes) -> Tri {
        let Values::Tags(want) = &self.values else {
            return malformed(notes);
        };
        let Some(ekus) = d.eku.as_deref() else {
            return missing(notes);
        };
        // An OID the fact holds that cannot be read could be any OID, so a
        // value it might be is unknown rather than absent.
        let mut unreadable = false;
        let have: Vec<String> = ekus
            .iter()
            .filter_map(|e| {
                let c = canonical_oid(e);
                unreadable |= c.is_none();
                c
            })
            .collect();
        if unreadable {
            notes.insert(Note::FactMalformed);
        }
        let held = |w: &String| {
            if have.contains(w) {
                Tri::Match
            } else if unreadable {
                Tri::Unknown
            } else {
                Tri::NoMatch
            }
        };
        if self.operator == crate::model::Operator::AllOf {
            want.iter().map(held).fold(Tri::Match, Tri::and)
        } else {
            want.iter().map(held).fold(Tri::NoMatch, Tri::or)
        }
    }
}

/// Which part of a signature a signer criterion reads: the publisher's
/// subject component and the TBS hash's position. Other fields read one
/// fact, and have the default selector.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Selector {
    component: SubjectComponent,
    position: TbsPosition,
}

impl Selector {
    /// The selector of a criterion, with each option kept only on the
    /// field it applies to.
    pub(crate) fn of(c: &Criterion) -> Self {
        let o = c.signer.as_deref();
        Self {
            component: o
                .and_then(|o| o.component)
                .filter(|_| c.field == Field::SignerPublisher)
                .unwrap_or_default(),
            position: o
                .and_then(|o| o.position)
                .filter(|_| c.field == Field::SignerTbsHash)
                .unwrap_or_default(),
        }
    }
}

/// What a signer field reads from one signature with `sel`, for the
/// decision trace: the value the criterion compared, or the values joined
/// with `, ` (the EKUs, or the TBS hashes of several positions), or `None`
/// if none is known.
pub(crate) fn observed(field: Field, sel: Selector, s: &SignerFact) -> Option<String> {
    let d = &s.details;
    let one = |v: &Option<String>| v.clone();
    let joined = |parts: Vec<&String>| {
        (!parts.is_empty()).then(|| {
            parts
                .iter()
                .map(|p| p.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        })
    };
    match field {
        Field::SignerPublisher => match sel.component {
            SubjectComponent::Cn => one(&s.publisher),
            SubjectComponent::O => one(&d.subject_organization),
            SubjectComponent::FullDn => one(&d.subject_dn),
        },
        Field::SignerIssuer => one(&s.issuer),
        Field::SignerLeafThumbprint => one(&s.leaf_thumbprint_sha256),
        Field::SignerLeafThumbprintSha1 => one(&d.leaf_thumbprint_sha1),
        Field::SignerPca => one(&d.pca),
        Field::SignerRootThumbprint => one(&d.root_thumbprint_sha256),
        Field::SignerRootThumbprintSha1 => one(&d.root_thumbprint_sha1),
        Field::SignerTbsHash => {
            let mid = d.intermediate_tbs_hashes.iter().flatten();
            match sel.position {
                TbsPosition::Leaf => one(&d.leaf_tbs_hash),
                TbsPosition::Root => one(&d.root_tbs_hash),
                TbsPosition::Intermediate => joined(mid.collect()),
                TbsPosition::Any => joined(
                    d.leaf_tbs_hash
                        .iter()
                        .chain(mid)
                        .chain(d.root_tbs_hash.iter())
                        .collect(),
                ),
            }
        }
        Field::SignerEku => d.eku.as_ref().map(|e| e.join(", ")),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
