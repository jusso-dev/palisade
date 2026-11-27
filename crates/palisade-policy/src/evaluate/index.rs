//! Candidate indexes, so evaluation is not linear in the number of rules
//! (#42).
//!
//! When an [`Evaluator`] is built, each rule is filed under the keys of
//! its **anchor** ([`crate::ops`] defines the anchor of one criterion): a
//! set of keys such that, whenever the rule's match tree is `Match`, the
//! object's facts contain at least one of them. The anchor of a tree is:
//!
//! - a criterion: its own anchor, if it has one;
//! - `all`: the anchor of one anchored child, since every child must
//!   match: the one on the cheapest facts (the path and the context come
//!   before hashes, then signers and the version resource), then the most
//!   selective (hashes, the leaf thumbprint, the publisher, other text,
//!   principals, path prefixes);
//! - `any`: the union of its children's anchors, if every child has one;
//! - `not`: none.
//!
//! The indexes, one map per field:
//!
//! - **hash**: decoded digest to rules, per hash field. A rule whose
//!   criterion lists 25 digests is filed 25 times, so one probe replaces
//!   scanning every hash rule.
//! - **signer**: leaf thumbprint, the leaf certificate's TBS hash
//!   (`signer.tbs_hash` at `position: leaf` only; a CA's TBS hash covers
//!   every file it signed, so it is evaluated always), and the folded
//!   publisher and issuer.
//! - **meta**: folded version-resource strings, file name and extension.
//! - **path**: folded literal path prefixes of `path.full` and
//!   `path.directory`, cut at a separator, with values that start with a
//!   path variable filed under the variable. Wildcards are filed under
//!   their literal part before the first wildcard character, so
//!   `C:\Program Files\*\x.exe` is under `C:\PROGRAM FILES`. A probe looks
//!   up every prefix of the folded fact that ends at a separator.
//! - **principal**: canonical SIDs and object IDs of `user.sid`,
//!   `user.primary_group`, `user.groups` and `device.groups`.
//! - **always**: rules with no anchor, every `deny` with
//!   `unknown_as: match`, which applies when its tree is `Unknown` and so
//!   cannot be skipped on a probe that finds nothing, and every rule with a
//!   `safety_critical` criterion, which counts as matching when its fact
//!   is unknown (#32). Each is evaluated
//!   for every object of its types. Validation warns when a policy has
//!   more than [`ALWAYS_EVAL_WARN`] of them (`unindexed_rules`).
//!
//! Mandatory denies have their own set of indexes, probed first.
//!
//! Candidate selection is the union of the probes, then the full match
//! tree is evaluated for each candidate only. A rule that is not a
//! candidate cannot be `Match`, and is not an always-evaluated deny, so it
//! does not apply: the matching rules are exactly those that a linear scan
//! finds, and the decision is the same (a property test checks this
//! against the linear scan, with the same decision and deciding rule).
//!
//! # Lazy facts
//!
//! [`Evaluator::evaluate_with`] takes the classes of facts that have been
//! computed ([`FactSet`]). Probing reads only facts that are there, and
//! never asks for any. Then:
//!
//! - If a rule of the object's type is anchored on a class that has not
//!   been computed, it could still match, unless the facts computed so far
//!   already make its tree `NoMatch` (only checked for rules that read
//!   classes besides their anchor's). Then that class is needed, with the
//!   classes it reads in that round or an earlier one. Its later rounds
//!   are asked for once it is a candidate whose tree is still `Unknown`.
//! - A candidate whose tree is `Unknown` needs the classes it reads that
//!   have not been computed. A tree that is `Match` or `NoMatch` is
//!   settled: Kleene logic is monotone, so more facts never change it.
//!
//! If anything is needed, the evaluator answers [`NeedFacts`] with the
//! needed classes of the earliest round ([`FactSet::ROUNDS`]). Every class
//! it asks for is read by a candidate. A rule only becomes a candidate
//! later if it was anchored on a class that was missing, and then its
//! classes were already needed; a settled tree stays settled. So every
//! class of a round is asked for the first time that round is reached,
//! and a decision takes at most three rounds after the cheap facts. If no
//! rule could match given the cheap facts, the decision is made without
//! asking for anything.

use std::collections::HashMap;

use crate::demand::FactSet;
use crate::facts::{ObjectFacts, PathFact, PathVariable};
use crate::model::{Action, Field, FieldClass, Match, ObjectType, UnknownAs};
use crate::ops::Tri;
use crate::ops::anchor::{LeafAnchor, decode_hex_into, leaf_anchor, probe_prefixes};
use crate::ops::scratch::{with_buffer, with_folded};

use super::{Compiled, Evaluator, Role, Subject};

/// More always-evaluated rules than this makes validation warn
/// (`unindexed_rules`).
pub const ALWAYS_EVAL_WARN: usize = 500;

/// The classes of facts are missing: compute them and evaluate again
/// (#42). Every class named is read by a rule that could still apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NeedFacts(pub FactSet);

/// The facts a policy can read, computed when it is loaded, so the agent
/// can decide to compute some eagerly (#42).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RequiredFacts {
    /// Every class any enabled rule reads.
    pub reads: FactSet,
    /// The classes that rules are indexed on.
    pub anchored: FactSet,
}

impl RequiredFacts {
    /// Whether any rule is indexed on a hash, so that most objects need
    /// hashing anyway and hashing eagerly at creation saves a round.
    #[must_use]
    pub const fn hash_eagerly(&self) -> bool {
        self.anchored.intersects(FactSet::HASHES)
    }
}

/// What an index holds, for reports and the `unindexed_rules` warning.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct IndexStats {
    /// Rules filed under at least one key.
    pub indexed_rules: usize,
    /// Rules evaluated for every object of their types.
    pub always_eval: usize,
    /// Keys over every index.
    pub keys: usize,
}

/// The candidates of one probe, kept inline.
pub(crate) type Postings = smallvec::SmallVec<[u32; 32]>;

/// The rules filed under one key: one rule, or a list.
#[derive(Clone, Debug)]
enum Posting {
    One(u32),
    Many(Vec<u32>),
}

impl Posting {
    fn push(&mut self, rule: u32) {
        match self {
            Self::One(first) if *first == rule => {}
            Self::One(first) => *self = Self::Many(vec![*first, rule]),
            Self::Many(list) => {
                if list.last() != Some(&rule) {
                    list.push(rule);
                }
            }
        }
    }

    fn rules(&self) -> &[u32] {
        match self {
            Self::One(rule) => core::slice::from_ref(rule),
            Self::Many(list) => list,
        }
    }
}

fn file<K: Eq + core::hash::Hash>(map: &mut HashMap<K, Posting>, key: K, rule: u32) {
    map.entry(key)
        .and_modify(|p| p.push(rule))
        .or_insert(Posting::One(rule));
}

/// Digests of one fixed length: a sorted array of `(digest, rule)` pairs,
/// built when the policy is loaded. A probe is a binary search, and one
/// entry costs the digest and four bytes, with no hash-table overhead, so
/// a million-entry hash set stays small.
#[derive(Debug)]
struct DigestMap {
    /// The digest length in bytes.
    len: usize,
    /// `len` bytes of digest, then the rule as four little-endian bytes,
    /// per entry: sorted by digest, then rule, without duplicates.
    entries: Vec<u8>,
    /// Whether `entries` is sorted (it is after [`Self::seal`]).
    sealed: bool,
}

impl DigestMap {
    fn for_len(len: usize) -> Option<Self> {
        matches!(len, 16 | 20 | 32 | 48 | 64).then(|| Self {
            len,
            entries: Vec::new(),
            sealed: false,
        })
    }

    const fn stride(&self) -> usize {
        self.len + 4
    }

    fn insert(&mut self, digest: &[u8], rule: u32) {
        if digest.len() == self.len {
            self.entries.extend_from_slice(digest);
            self.entries.extend_from_slice(&rule.to_le_bytes());
            self.sealed = false;
        }
    }

    /// Sorts the entries and drops duplicates, once every rule is filed.
    fn seal(&mut self) {
        let stride = self.stride();
        let mut rows: Vec<&[u8]> = self.entries.chunks_exact(stride).collect();
        rows.sort_unstable();
        rows.dedup();
        let mut sorted = Vec::with_capacity(rows.len() * stride);
        for row in rows {
            sorted.extend_from_slice(row);
        }
        sorted.shrink_to_fit();
        self.entries = sorted;
        self.sealed = true;
    }

    fn rows(&self) -> usize {
        self.entries.len() / self.stride()
    }

    fn digest(&self, i: usize) -> &[u8] {
        let at = i * self.stride();
        &self.entries[at..at + self.len]
    }

    fn rule(&self, i: usize) -> u32 {
        let at = i * self.stride() + self.len;
        let mut b = [0u8; 4];
        b.copy_from_slice(&self.entries[at..at + 4]);
        u32::from_le_bytes(b)
    }

    /// Adds to `out` the rules filed under the digest written as `hex`.
    /// Returns `false` if `hex` is not a digest of this length. Does not
    /// allocate.
    fn probe_hex(&self, hex: &str, out: &mut Postings) -> bool {
        let mut key = [0u8; 64];
        let Some(key) = key.get_mut(..self.len) else {
            return false;
        };
        if decode_hex_into(hex, key).is_none() {
            return false;
        }
        debug_assert!(self.sealed, "probed before sealing");
        // The first row whose digest is not below the key.
        let (mut lo, mut hi) = (0, self.rows());
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.digest(mid) < &*key {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        while lo < self.rows() && self.digest(lo) == &*key {
            out.push(self.rule(lo));
            lo += 1;
        }
        true
    }

    const fn digest_len(&self) -> usize {
        self.len
    }

    /// The number of distinct digests.
    fn len(&self) -> usize {
        let mut n = 0;
        for i in 0..self.rows() {
            if i == 0 || self.digest(i) != self.digest(i - 1) {
                n += 1;
            }
        }
        n
    }
}

/// Every index of one tier: the mandatory denies, or the other rules.
#[derive(Debug, Default)]
struct IndexSet {
    hash: Vec<(Field, DigestMap)>,
    thumbprint: HashMap<[u8; 32], Posting>,
    /// Leaf TBS hashes, as lower-case hex.
    leaf_tbs: HashMap<String, Posting>,
    text: Vec<(Field, HashMap<String, Posting>)>,
    path: Vec<(Field, HashMap<String, Posting>)>,
    path_variable: Vec<(Field, PathVariable, Vec<u32>)>,
    principal: Vec<(Field, HashMap<String, Posting>)>,
    always: Vec<u32>,
}

impl IndexSet {
    /// Files `rule` under the keys of `anchor`. Returns `false`, filing
    /// nothing, if the anchor cannot be filed (a digest of a length no
    /// hash has), so the caller evaluates the rule always instead.
    fn file(&mut self, anchor: &LeafAnchor, rule: u32) -> bool {
        match anchor {
            LeafAnchor::Hash(field, digests) => {
                let len = digests.first().map_or(0, Vec::len);
                if digests.iter().any(|d| d.len() != len) {
                    return false;
                }
                let Some(i) = self.slot_hash(*field, len) else {
                    return false;
                };
                for d in digests {
                    self.hash[i].1.insert(d, rule);
                }
            }
            LeafAnchor::Thumbprint(prints) => {
                for p in prints {
                    file(&mut self.thumbprint, *p, rule);
                }
            }
            LeafAnchor::LeafTbs(hashes) => {
                for h in hashes {
                    file(&mut self.leaf_tbs, h.clone(), rule);
                }
            }
            LeafAnchor::Text(field, values) => {
                let map = slot(&mut self.text, *field);
                for v in values {
                    file(map, v.clone(), rule);
                }
            }
            LeafAnchor::Path {
                field,
                prefixes,
                variables,
            } => {
                let map = slot(&mut self.path, *field);
                for p in prefixes {
                    file(map, p.clone(), rule);
                }
                for v in variables {
                    match self
                        .path_variable
                        .iter_mut()
                        .find(|(f, var, _)| f == field && var == v)
                    {
                        Some((_, _, rules)) => {
                            if rules.last() != Some(&rule) {
                                rules.push(rule);
                            }
                        }
                        None => self.path_variable.push((*field, *v, vec![rule])),
                    }
                }
            }
            LeafAnchor::Principal(field, values) => {
                let map = slot(&mut self.principal, *field);
                for v in values {
                    file(map, v.clone(), rule);
                }
            }
        }
        true
    }

    /// Whether [`Self::file`] can file `anchor`: every digest has the
    /// length of a hash, the same for one field.
    fn fileable(anchor: &LeafAnchor) -> bool {
        match anchor {
            LeafAnchor::Hash(_, digests) => {
                let len = digests.first().map_or(0, Vec::len);
                DigestMap::for_len(len).is_some() && digests.iter().all(|d| d.len() == len)
            }
            _ => true,
        }
    }

    fn slot_hash(&mut self, field: Field, len: usize) -> Option<usize> {
        if let Some(i) = self.hash.iter().position(|(f, _)| *f == field) {
            return (self.hash[i].1.digest_len() == len).then_some(i);
        }
        self.hash.push((field, DigestMap::for_len(len)?));
        Some(self.hash.len() - 1)
    }

    /// Sorts the digest arrays, once every rule is filed.
    fn seal(&mut self) {
        for (_, map) in &mut self.hash {
            map.seal();
        }
        for (_, map) in &mut self.text {
            map.shrink_to_fit();
        }
        for (_, map) in &mut self.path {
            map.shrink_to_fit();
        }
    }

    fn keys(&self) -> usize {
        self.hash.iter().map(|(_, m)| m.len()).sum::<usize>()
            + self.thumbprint.len()
            + self.leaf_tbs.len()
            + self.text.iter().map(|(_, m)| m.len()).sum::<usize>()
            + self.path.iter().map(|(_, m)| m.len()).sum::<usize>()
            + self.path_variable.len()
            + self.principal.iter().map(|(_, m)| m.len()).sum::<usize>()
    }

    /// Adds to `out` every rule filed under a key the facts hold, reading
    /// only the classes in `available`. A fact that is malformed (a digest
    /// of the wrong length) finds nothing: a criterion on it is `Unknown`,
    /// never `Match`.
    ///
    /// Returns whether a fact that rules of this set are filed under is
    /// missing, malformed or unresolved although its class was computed.
    /// Those rules are not candidates, because they cannot be `Match`; but
    /// their trees may be `Unknown`, so the decision rests on an unknown
    /// fact and must not be cached.
    fn probe(&self, subject: &Subject<'_>, available: FactSet, out: &mut Postings) -> bool {
        let facts = subject.facts;
        let mut unknown = false;
        for (field, map) in &self.hash {
            if !available.contains(FactSet::hash(*field)) {
                continue;
            }
            match facts.get(*field) {
                Some(hex) => unknown |= !map.probe_hex(hex, out),
                None => unknown = true,
            }
        }
        let signer_fields = !self.thumbprint.is_empty()
            || !self.leaf_tbs.is_empty()
            || find(&self.text, Field::SignerPublisher).is_some()
            || find(&self.text, Field::SignerIssuer).is_some();
        if signer_fields && available.contains(FactSet::SIGNERS) {
            if facts.signers.is_none() {
                unknown = true;
            }
            for signer in facts
                .signers
                .iter()
                .flatten()
                .filter(|s| s.status.is_trusted())
            {
                if !self.leaf_tbs.is_empty() {
                    match signer.details.leaf_tbs_hash.as_deref() {
                        // As the evaluator reads it: a digest, compared
                        // ignoring case.
                        Some(hex)
                            if matches!(hex.len(), 40 | 64 | 96 | 128)
                                && hex.bytes().all(|b| b.is_ascii_hexdigit()) =>
                        {
                            let mut key = [0u8; 128];
                            let key = &mut key[..hex.len()];
                            key.copy_from_slice(hex.as_bytes());
                            key.make_ascii_lowercase();
                            if let Some(p) = core::str::from_utf8(key)
                                .ok()
                                .and_then(|k| self.leaf_tbs.get(k))
                            {
                                out.extend_from_slice(p.rules());
                            }
                        }
                        _ => unknown = true,
                    }
                }
                if !self.thumbprint.is_empty() {
                    let mut key = [0u8; 32];
                    match signer.leaf_thumbprint_sha256.as_deref() {
                        Some(hex) if decode_hex_into(hex, &mut key).is_some() => {
                            if let Some(p) = self.thumbprint.get(&key) {
                                out.extend_from_slice(p.rules());
                            }
                        }
                        _ => unknown = true,
                    }
                }
                for (field, fact) in [
                    (Field::SignerPublisher, signer.publisher.as_deref()),
                    (Field::SignerIssuer, signer.issuer.as_deref()),
                ] {
                    if let Some(map) = find(&self.text, field) {
                        match fact {
                            Some(fact) => with_folded(fact, false, |f| lookup(map, f, out)),
                            None => unknown = true,
                        }
                    }
                }
            }
        }
        for (field, map) in &self.text {
            let field = *field;
            if !available.contains(FactSet::of_field(field)) {
                continue;
            }
            match field.class() {
                FieldClass::FileName => {
                    unknown |= !for_each_path_form(facts.path.as_ref(), |path| {
                        // A bare root has no file name: unknown.
                        let Some(name) = path.file_name() else {
                            return false;
                        };
                        let text = if field == Field::PathFileName {
                            name
                        } else {
                            path.extension().unwrap_or("")
                        };
                        with_folded(text, false, |f| lookup(map, f, out));
                        true
                    });
                }
                _ if matches!(field, Field::SignerPublisher | Field::SignerIssuer) => {}
                _ => match facts.get(field) {
                    Some(fact) => with_folded(fact, false, |f| lookup(map, f, out)),
                    None => unknown = true,
                },
            }
        }
        if !self.path.is_empty() {
            unknown |= !for_each_path_form(facts.path.as_ref(), |path| {
                let mut known = true;
                for (field, map) in &self.path {
                    let text = match field {
                        Field::PathDirectory if path.file_name().is_some() => {
                            path.directory().unwrap_or("")
                        }
                        // A bare root has no directory: unknown.
                        Field::PathDirectory => {
                            known = false;
                            continue;
                        }
                        _ => path.as_str(),
                    };
                    with_folded(text, false, |folded| {
                        for prefix in probe_prefixes(folded) {
                            lookup(map, prefix, out);
                        }
                    });
                }
                known
            });
        }
        for (_, variable, rules) in &self.path_variable {
            if subject.variables.get(*variable).is_empty() {
                // The rule's value cannot be expanded: unknown.
                unknown = true;
            } else {
                out.extend_from_slice(rules);
            }
        }
        if !self.principal.is_empty() {
            let user = &subject.context.user;
            let device = &subject.context.device;
            for (field, map) in &self.principal {
                match field {
                    Field::UserSid | Field::UserPrimaryGroup => {
                        let fact = if *field == Field::UserSid {
                            user.sid.as_deref()
                        } else {
                            user.primary_group.as_deref()
                        };
                        match fact {
                            Some(fact) => with_buffer(|sid| {
                                if crate::context::normalize_sid_into(fact, sid) {
                                    lookup(map, sid, out);
                                } else {
                                    unknown = true;
                                }
                            }),
                            None => unknown = true,
                        }
                    }
                    Field::UserGroups | Field::DeviceGroups => {
                        let set = if *field == Field::UserGroups {
                            user.groups.as_deref()
                        } else {
                            device.groups.as_deref()
                        };
                        match set {
                            Some(set) => with_buffer(|m| {
                                for member in set {
                                    if crate::context::normalize_principal_into(member, m) {
                                        lookup(map, m, out);
                                    } else {
                                        unknown = true;
                                    }
                                }
                            }),
                            None => unknown = true,
                        }
                    }
                    _ => {}
                }
            }
        }
        out.extend_from_slice(&self.always);
        unknown
    }
}

fn slot<V: Default>(list: &mut Vec<(Field, V)>, field: Field) -> &mut V {
    let i = match list.iter().position(|(f, _)| *f == field) {
        Some(i) => i,
        None => {
            list.push((field, V::default()));
            list.len() - 1
        }
    };
    &mut list[i].1
}

fn find<V>(list: &[(Field, V)], field: Field) -> Option<&V> {
    list.iter().find(|(f, _)| *f == field).map(|(_, v)| v)
}

fn lookup(map: &HashMap<String, Posting>, key: &str, out: &mut Postings) {
    if let Some(p) = map.get(key) {
        out.extend_from_slice(p.rules());
    }
}

/// Runs `f` with each spelling of the path that path criteria test: the
/// path and its alias, if they are drive or UNC paths and the short name
/// was resolved. Otherwise path criteria are `Unknown`, never `Match`.
/// Returns whether the path was known: there is one, it is resolved, and
/// `f` said every spelling was known.
fn for_each_path_form(
    path: Option<&PathFact>,
    mut f: impl FnMut(&palisade_core::path::NormalizedPath) -> bool,
) -> bool {
    let Some(path) = path else {
        return false;
    };
    if path.short_name_unresolved || !path.path.is_resolved() {
        return false;
    }
    let mut known = f(&path.path);
    if let Some(alias) = path.alias.as_ref().filter(|a| a.is_resolved()) {
        known &= f(alias);
    }
    known
}

/// The anchor of a match tree: the keys one of which the facts must hold
/// for the tree to be `Match`. See the module documentation.
pub(crate) fn tree_anchor(tree: &Match) -> Option<Vec<LeafAnchor>> {
    match tree {
        Match::Criterion(c) => leaf_anchor(c).map(|a| vec![a]),
        Match::All(children) => children
            .iter()
            .filter_map(tree_anchor)
            .min_by_key(|set| (set.iter().map(LeafAnchor::rank).max(), set.len())),
        Match::Any(children) => {
            let mut out = Vec::new();
            for child in children {
                out.extend(tree_anchor(child)?);
            }
            Some(out)
        }
        // `not` identifies nothing.
        _ => None,
    }
}

/// Whether the evaluator files `rule` in an index rather than evaluating it
/// for every object: it has an anchor that can be filed, and it is not a
/// deny with `unknown_as: match`. Validation counts the rules that are not
/// (`unindexed_rules`).
pub(crate) fn is_indexed(rule: &crate::model::Rule) -> bool {
    let fails_closed = matches!(&rule.action, Action::Deny(o) if o.unknown_as == UnknownAs::Match)
        || safety_critical(&rule.match_);
    !fails_closed
        && tree_anchor(&rule.match_).is_some_and(|leaves| leaves.iter().all(IndexSet::fileable))
}

/// Whether a criterion of `tree` is `safety_critical` (#32): in a mandatory
/// deny it counts as matching when its fact is unknown, so the rule can
/// apply with none of its anchor's keys in the facts.
fn safety_critical(tree: &Match) -> bool {
    let mut stack = vec![tree];
    while let Some(node) = stack.pop() {
        if matches!(node, Match::Criterion(c) if c.safety_critical) {
            return true;
        }
        stack.extend(node.children());
    }
    false
}

/// The classes a rule reads: one per criterion field, and the path ACL if
/// the rule lets an object run, trusts it or excludes it and tests a
/// path.
pub(super) fn reads(rule: &crate::model::Rule) -> FactSet {
    let mut set = FactSet::EMPTY;
    let mut stack = vec![&rule.match_];
    while let Some(node) = stack.pop() {
        if let Match::Criterion(c) = node {
            set |= FactSet::of_field(c.field);
            if rule.action.kind().needs_identity()
                && matches!(c.field.class(), FieldClass::Path | FieldClass::FileName)
            {
                set |= FactSet::PATH_ACL;
            }
        }
        stack.extend(node.children());
    }
    set
}

/// The slot of an object type in per-type tables.
fn type_slot(t: ObjectType) -> usize {
    ObjectType::ALL.iter().position(|x| *x == t).unwrap_or(0)
}

/// The number of classes a rule can be anchored on: one bit each.
const CLASS_BITS: usize = 32;

/// The candidate indexes of one policy.
#[derive(Debug)]
pub(super) struct RuleIndex {
    mandatory: IndexSet,
    ordinary: IndexSet,
    /// Per rule: the classes it reads.
    reads: Vec<FactSet>,
    /// Per tier: the rules anchored on a class that may not have been
    /// computed yet ([`Pending`]).
    pending: [Pending; 2],
    stats: IndexStats,
    required: RequiredFacts,
}

/// The rules of one tier anchored on each class, for the lazy fact
/// protocol: when the class has not been computed, they could still match.
#[derive(Debug)]
struct Pending {
    /// Per object type, per anchor class bit: `None` if no rule of that
    /// type is anchored on the class, or every such rule reads other
    /// classes too; otherwise the class and the classes those rules read
    /// in the same or an earlier round. Asking for those together means no
    /// rule that surfaces later needs an earlier round again, so a
    /// decision takes at most three rounds.
    whole: Vec<[Option<FactSet>; CLASS_BITS]>,
    /// Per object type, per anchor class bit: the rules anchored on the
    /// class that also read classes outside it, so the facts computed so
    /// far may already settle them. Each is evaluated when its anchor
    /// class is missing, and only needs the class if its tree is `Unknown`:
    /// `NoMatch` rules it out, and `Match` makes it a candidate already.
    mixed: Vec<[Vec<u32>; CLASS_BITS]>,
}

impl Pending {
    fn new() -> Self {
        Self {
            whole: vec![[None; CLASS_BITS]; ObjectType::ALL.len()],
            mixed: (0..ObjectType::ALL.len())
                .map(|_| core::array::from_fn(|_| Vec::new()))
                .collect(),
        }
    }
}

/// The classes of the rounds up to the one `class` is asked for in: none
/// for a cheap class.
fn rounds_to(class: FactSet) -> FactSet {
    FactSet::ROUNDS
        .iter()
        .take(class.round())
        .fold(FactSet::EMPTY, |acc, r| acc | *r)
}

/// The bit of a single class.
fn bit(class: FactSet) -> usize {
    class.bits().trailing_zeros() as usize
}

impl RuleIndex {
    pub(super) fn build(rules: &[Compiled<'_>]) -> Self {
        let mut mandatory = IndexSet::default();
        let mut ordinary = IndexSet::default();
        let mut reads_all = Vec::with_capacity(rules.len());
        let mut pending = [Pending::new(), Pending::new()];
        let mut stats = IndexStats::default();
        let mut required = RequiredFacts {
            reads: FactSet::EMPTY,
            anchored: FactSet::EMPTY,
        };
        for (i, compiled) in rules.iter().enumerate() {
            let rule = u32::try_from(i).unwrap_or(u32::MAX);
            let tier = Tier::of(compiled.role);
            let set = match tier {
                Tier::Mandatory => &mut mandatory,
                Tier::Ordinary => &mut ordinary,
            };
            let reads = reads(compiled.rule);
            reads_all.push(reads);
            required.reads |= reads;
            // A deny that applies on `Unknown` cannot be skipped when a
            // probe finds nothing, and every leaf of an anchor must be
            // filed, or the rule could be missed.
            let anchor = if is_indexed(compiled.rule) {
                tree_anchor(&compiled.rule.match_)
            } else {
                None
            };
            let Some(anchor) = anchor else {
                set.always.push(rule);
                stats.always_eval += 1;
                continue;
            };
            stats.indexed_rules += 1;
            let mut classes = FactSet::EMPTY;
            for leaf in &anchor {
                let filed = set.file(leaf, rule);
                debug_assert!(filed, "a fileable anchor is filed");
                classes |= FactSet::of_field(leaf.field());
            }
            required.anchored |= classes;
            let pending = &mut pending[tier as usize];
            for t in ObjectType::ALL {
                if !compiled.rule.object_types.is_empty()
                    && !compiled.rule.object_types.contains(&t)
                {
                    continue;
                }
                for class in classes.classes() {
                    // A rule that reads nothing besides this class cannot
                    // be settled without it; one that reads other classes
                    // (another branch of an `any`, a cheap criterion of an
                    // `all`) may be.
                    if reads.difference(class).is_empty() {
                        let cell =
                            pending.whole[type_slot(t)][bit(class)].get_or_insert(FactSet::EMPTY);
                        *cell |= class | reads.intersection(rounds_to(class));
                    } else {
                        pending.mixed[type_slot(t)][bit(class)].push(rule);
                    }
                }
            }
        }
        mandatory.seal();
        ordinary.seal();
        stats.keys = mandatory.keys() + ordinary.keys();
        Self {
            mandatory,
            ordinary,
            reads: reads_all,
            pending,
            stats,
            required,
        }
    }

    pub(super) const fn stats(&self) -> IndexStats {
        self.stats
    }

    pub(super) const fn required(&self) -> RequiredFacts {
        self.required
    }
}

/// The classes computed for `facts`: those `declared`, the cheap ones,
/// and any class whose facts are present.
pub(super) fn available(facts: &ObjectFacts, declared: FactSet) -> FactSet {
    let mut set = declared | FactSet::CHEAP;
    for field in facts.fields() {
        set |= FactSet::hash(field);
    }
    if facts.signers.is_some() {
        set |= FactSet::SIGNERS;
    }
    if facts
        .fields()
        .any(|f| FactSet::of_field(f) == FactSet::METADATA)
    {
        set |= FactSet::METADATA;
    }
    // Without a path there is no path criterion to decide, so its ACL is
    // never needed.
    if facts
        .path
        .as_ref()
        .is_none_or(|p| p.user_writable.is_some())
    {
        set |= FactSet::PATH_ACL;
    }
    set
}

/// The rules selected for one object.
pub(super) struct Selection<'a, 'p> {
    /// The rules that apply, in rule order.
    pub(super) matched: super::Rules<'a, 'p>,
    /// Whether a candidate's tree or scopes were `Unknown`: the decision
    /// rests on a fact that is missing or cannot be trusted, so it must not
    /// be cached.
    pub(super) unknown: bool,
    /// The scope notes (#38) of every candidate whose tree was not
    /// `NoMatch`. A rule that is not a candidate cannot be `Match`, so its
    /// scopes never kept a matching rule from applying.
    pub(super) notes: crate::scope::ScopeNotes,
}

/// Why selection stopped before it decided.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Stop {
    /// More facts are needed.
    Need(NeedFacts),
    /// The watchdog's budget ran out.
    Timeout(Timeout),
}

/// Where the watchdog stopped a selection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Timeout {
    /// The rule whose tree was evaluated last, when the budget was found
    /// spent.
    pub(crate) slow_rule: crate::decision::RuleRef,
    /// Whether every mandatory deny was settled: evaluated, and not
    /// waiting on a fact that has not been computed.
    pub(crate) mandatory_done: bool,
    /// The ordinals of the mandatory denies that matched. A timeout is
    /// rare, so this may allocate.
    pub(crate) mandatory: Vec<u32>,
}

impl<'p> Evaluator<'p> {
    /// The rules that apply to the subject, found through the indexes,
    /// with every fact taken as computed.
    pub(super) fn select_all<'a>(&'a self, subject: &Subject<'_>) -> Selection<'a, 'p> {
        match self.select(subject, FactSet::ALL, &mut |_| false) {
            Ok(selection) => selection,
            // With every class computed nothing is ever needed, and nothing
            // stops the selection; if it did, the linear scan decides.
            Err(_) => {
                let (matched, notes) = self.matching_with_notes(subject);
                Selection {
                    matched: matched.into_iter().collect(),
                    unknown: true,
                    notes,
                }
            }
        }
    }

    /// Selects the rules that apply, reading the classes in `declared`
    /// and those present in the facts. See the module documentation.
    /// `expired` is asked after each match tree is evaluated, with its
    /// rule, and stops the selection when it returns `true`.
    pub(super) fn select<'a>(
        &'a self,
        subject: &Subject<'_>,
        declared: FactSet,
        expired: &mut dyn FnMut(&crate::decision::RuleRef) -> bool,
    ) -> Result<Selection<'a, 'p>, Stop> {
        let available = available(subject.facts, declared);
        let index = &self.index;
        let slot = type_slot(subject.object_type);

        let mut missing = FactSet::EMPTY;
        let mut hits: Postings = smallvec::SmallVec::new();
        let mut unknown = false;
        let mut notes = crate::scope::ScopeNotes::default();
        // The mandatory tier first, then the rest, each in rule order, so a
        // mandatory deny is always found before the watchdog can stop the
        // selection on an ordinary rule. The budget is checked after every
        // match tree.
        let mut mandatory_done = false;
        for tier in [Tier::Mandatory, Tier::Ordinary] {
            let set = match tier {
                Tier::Mandatory => &index.mandatory,
                Tier::Ordinary => &index.ordinary,
            };
            let stop = |rule: &Compiled<'_>, hits: &Postings, done: bool| {
                Stop::Timeout(Timeout {
                    slow_rule: rule.reference,
                    mandatory_done: done,
                    mandatory: hits
                        .iter()
                        .copied()
                        .filter(|&h| {
                            self.rules
                                .get(h as usize)
                                .is_some_and(|r| r.role == Role::Mandatory)
                        })
                        .collect(),
                })
            };
            let mut candidates: Postings = smallvec::SmallVec::new();
            unknown |= set.probe(subject, available, &mut candidates);
            candidates.sort_unstable();
            candidates.dedup();
            for &i in &candidates {
                let Some(rule) = self.rules.get(i as usize) else {
                    continue;
                };
                if (!rule.rule.object_types.is_empty()
                    && !rule.rule.object_types.contains(&subject.object_type))
                    || !self.live(rule)
                {
                    continue;
                }
                // As `Compiled::applies`: the scopes first (#38), and the
                // tree only if they could match or noticed something.
                let scope = rule.scope_eval(subject);
                let tree = if scope.result == Tri::NoMatch && scope.notes.is_empty() {
                    Tri::NoMatch
                } else {
                    rule.tree_result(subject)
                };
                if tree != Tri::NoMatch {
                    notes.extend(scope.notes);
                }
                match scope.result.and(tree) {
                    Tri::Match => hits.push(i),
                    Tri::NoMatch => {}
                    Tri::Unknown => {
                        // Only the tree reads facts that can be computed;
                        // an unknown scope is settled.
                        let need = if tree == Tri::Unknown {
                            index.reads[i as usize].difference(available)
                        } else {
                            FactSet::EMPTY
                        };
                        if need.is_empty() {
                            unknown = true;
                            if rule.unknown_as == UnknownAs::Match {
                                hits.push(i);
                            }
                        } else {
                            missing |= need;
                        }
                    }
                }
                if expired(&rule.reference) {
                    return Err(stop(rule, &hits, mandatory_done));
                }
            }
            // Rules of this tier anchored on a class that is not computed
            // could still match, unless the facts computed so far already
            // settle them.
            let pending = &index.pending[tier as usize];
            for (b, whole) in pending.whole[slot].iter().enumerate() {
                let class = FactSet::from_bits(1 << b);
                if available.contains(class) {
                    continue;
                }
                if let Some(need) = whole {
                    missing |= class | *need;
                }
            }
            for (b, rules) in pending.mixed[slot].iter().enumerate() {
                let class = FactSet::from_bits(1 << b);
                if available.contains(class) {
                    continue;
                }
                for &i in rules {
                    let need = class | index.reads[i as usize].intersection(rounds_to(class));
                    if missing.contains(need.difference(available)) {
                        continue;
                    }
                    let Some(rule) = self.rules.get(i as usize) else {
                        continue;
                    };
                    // A rule that is inactive, or that its scopes take out
                    // whatever its tree says, needs nothing.
                    let out = !self.live(rule) || {
                        let scope = rule.scope_eval(subject);
                        scope.result == Tri::NoMatch && scope.notes.is_empty()
                    };
                    if !out && rule.tree_result(subject) == Tri::Unknown {
                        missing |= need;
                    }
                    if expired(&rule.reference) {
                        return Err(stop(rule, &hits, mandatory_done));
                    }
                }
            }
            if tier == Tier::Mandatory {
                // Settled if no mandatory deny waits on a missing fact.
                mandatory_done = missing.difference(available).is_empty();
            }
        }
        // Facts the stages after selection read (#39): the self-allow
        // check reads the hash and the signers of an object of a pinned
        // type, and stage 6 reads the path's ACL for its location class
        // unless the agent gave the class. The pin is checked between the
        // mandatory tier and the rest, so it is asked for unless a
        // mandatory deny already matched.
        let mandatory_hit = hits.iter().any(|&h| {
            self.rules
                .get(h as usize)
                .is_some_and(|r| r.role == Role::Mandatory)
        });
        if !mandatory_hit {
            missing |= self.after_selection(subject);
        }
        missing = missing.difference(available);

        if !missing.is_empty() {
            return Err(Stop::Need(NeedFacts(missing.first_round())));
        }
        // Rules of both tiers in rule order, as a linear scan finds them.
        hits.sort_unstable();
        let matched = hits
            .iter()
            .filter_map(|&i| self.rules.get(i as usize))
            .collect();
        Ok(Selection {
            matched,
            unknown,
            notes,
        })
    }
}

impl Evaluator<'_> {
    /// The classes the self-allow check and stage 6 read for `subject`,
    /// besides those of the rules (#39), where they can change the
    /// decision. Stage 6 only decides when no rule did, but asking for its
    /// facts up front keeps the rounds in order.
    fn after_selection(&self, subject: &Subject<'_>) -> FactSet {
        let mut set = FactSet::EMPTY;
        if self
            .self_images
            .iter()
            .any(|i| i.object_type() == subject.object_type)
        {
            set |= FactSet::hash(Field::HashSha256) | FactSet::SIGNERS;
        }
        // A prompt offers `allow_always_local` only with the file's
        // SHA-256, which its directive carries.
        if self.prompts {
            set |= FactSet::hash(Field::HashSha256);
        }
        // Without the ACL a file is `user_writable_other`, the stricter
        // reading ([`crate::unknown::location`]), so the ACL only matters
        // when a level depends on the location.
        let classified = subject
            .facts
            .location_class
            .as_ref()
            .is_some_and(|c| !c.is_empty());
        if subject.facts.path.is_some() && !classified && self.by_location {
            set |= FactSet::PATH_ACL;
        }
        set
    }
}

/// The two tiers of candidates, evaluated in this order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tier {
    Mandatory = 0,
    Ordinary = 1,
}

impl Tier {
    fn of(role: Role) -> Self {
        if role == Role::Mandatory {
            Self::Mandatory
        } else {
            Self::Ordinary
        }
    }
}

impl Compiled<'_> {
    /// The tree's result for the subject, with this rule's reading of
    /// unparseable versions.
    fn tree_result(&self, subject: &Subject<'_>) -> Tri {
        let ctx = crate::ops::EvalContext {
            action: self.rule.action.kind(),
            variables: subject.variables,
            context: subject.context,
        };
        self.tree.eval(
            subject.facts,
            &ctx,
            self.unparseable,
            self.role == Role::Mandatory,
        )
    }
}

#[cfg(test)]
pub(crate) mod tests;
