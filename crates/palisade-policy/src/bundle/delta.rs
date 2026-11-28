//! Deltas between two bundles (#43).
//!
//! [`diff`] describes how to turn one bundle into another, and [`apply`]
//! does it. A [`BundleDelta`] names the bundle it applies to and the
//! bundle it produces by their [`bundle_hash`]es. `apply` takes the base as
//! the bytes the agent verified and refuses any other base, and checks that
//! the result hashes to `result_bundle_hash` before it returns it, so a
//! delta can only ever give the exact canonical bytes of the new bundle,
//! or an error.
//!
//! Operations work on the canonical body:
//!
//! - rules are added or replaced (`put_rule`) and removed (`remove_rule`)
//!   by rule ID, within their rule set;
//! - a rule set whose own fields changed, or that is new, is replaced
//!   whole, without its rules (`put_rule_set`), and one that is gone is
//!   removed (`remove_rule_set`);
//! - the header, the policy (without its rule sets), the source revisions
//!   and the metadata digest are replaced whole when they changed;
//! - inlined libraries are added or replaced (`put_library`) and removed
//!   (`remove_library`) by ID and version. A new version of a hash set
//!   (#368) is sent as the digests it adds to and removes from a version
//!   the base holds (`patch_hash_set`) when that is smaller than the set.
//!   The patch is strict (every digest removed is in the base set, none
//!   added is), and the result is checked against `result_bundle_hash`
//!   like every other operation, so a patch can only rebuild the exact
//!   set the server signed.
//!
//! The delta is itself encoded with [`to_bytes`](BundleDelta::to_bytes),
//! canonically, so #225 can sign it with both hashes. The server sends a
//! delta only when the agent's bundle is its base and it is smaller than
//! half the full bundle ([`worth_sending`]).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::cbor::{self, Limits, Value};
use super::format::SetContent;
use super::format::{
    Body, BundleError, BundleLimits, Header, InlineLibrary, PolicyBundle, Sha256Digest,
    SourceRevisions, bundle_hash,
};
use super::serial;
use crate::hashset::{Digests, DigestsError};
use crate::library::LibraryId;
use crate::model::{Policy, PolicyDocument, Rule, RuleId, RuleSet, RuleSetId};

/// One change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    /// Adds or replaces a rule set's own fields. Its `rules` are empty
    /// here: they stay as they were, and change by `put_rule`.
    PutRuleSet(Box<RuleSet>),
    /// Removes a rule set and its rules.
    RemoveRuleSet(RuleSetId),
    /// Adds or replaces a rule in a rule set.
    PutRule(RuleSetId, Box<Rule>),
    /// Removes a rule from a rule set.
    RemoveRule(RuleSetId, RuleId),
    /// Replaces the policy, without its rule sets.
    PutPolicy(Box<Policy>),
    /// Replaces the inlined libraries.
    PutLibraries(Vec<InlineLibrary>),
    /// Replaces the source revisions.
    PutSources(SourceRevisions),
    /// Adds or replaces one inlined library version.
    PutLibrary(Box<InlineLibrary>),
    /// Removes one inlined library version.
    RemoveLibrary(LibraryId, u32),
    /// Adds or replaces a hash set version (#368), built from another
    /// version of the same set that the base holds.
    PatchHashSet(Box<HashSetPatch>),
}

/// A hash set version as the change from another version of the same set
/// (#368).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HashSetPatch {
    /// The set.
    pub id: LibraryId,
    /// The version the base holds, which the patch starts from.
    pub base_version: u32,
    /// The version the patch gives.
    pub resolved_version: u32,
    /// The digests the new version adds.
    pub add: Digests,
    /// The digests the new version removes.
    pub remove: Digests,
}

/// How to turn one bundle into another.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleDelta {
    /// The hash of the bundle it applies to.
    pub base_bundle_hash: Sha256Digest,
    /// The hash of the bundle it produces.
    pub result_bundle_hash: Sha256Digest,
    /// The header of the result.
    pub header: Header,
    /// The metadata digest of the result.
    pub metadata_digest: Sha256Digest,
    /// The changes, in canonical order.
    pub ops: Vec<Op>,
}

/// Why a delta could not be made or applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeltaError {
    /// The delta is for another base bundle.
    WrongBase,
    /// An operation names a rule set that the base does not have.
    MissingRuleSet(RuleSetId),
    /// An operation removes a rule that the base does not have.
    MissingRule(RuleId),
    /// An operation removes or patches a library version that the base
    /// does not have, or patches one that is not a hash set.
    MissingLibrary(LibraryId, u32),
    /// A hash set patch does not fit its base set (#368).
    Patch(DigestsError),
    /// The result does not hash to `result_bundle_hash`.
    ResultMismatch,
    /// A bundle does not encode.
    Encode(serial::Error),
    /// The encoded delta does not read.
    Decode(BundleError),
}

impl core::fmt::Display for DeltaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongBase => f.write_str("the delta is for another base bundle"),
            Self::MissingRuleSet(id) => write!(f, "the base has no rule set {id}"),
            Self::MissingRule(id) => write!(f, "the base has no rule {id}"),
            Self::MissingLibrary(id, v) => write!(f, "the base has no library {id} v{v} to change"),
            Self::Patch(e) => write!(f, "the hash set patch does not apply: {e}"),
            Self::ResultMismatch => f.write_str("the result does not match the delta's hash"),
            Self::Encode(e) => write!(f, "the bundle does not encode: {e}"),
            Self::Decode(e) => write!(f, "the delta does not read: {e}"),
        }
    }
}

impl std::error::Error for DeltaError {}

fn index(doc: &PolicyDocument) -> BTreeMap<RuleSetId, (&RuleSet, BTreeMap<RuleId, &Rule>)> {
    doc.rule_sets
        .iter()
        .map(|s| (s.id, (s, s.rules.iter().map(|r| (r.id, r)).collect())))
        .collect()
}

fn without_rules(set: &RuleSet) -> RuleSet {
    RuleSet {
        rules: Vec::new(),
        ..set.clone()
    }
}

/// The delta from `old` to `new`.
///
/// # Errors
///
/// [`DeltaError::Encode`] if either bundle does not encode.
pub fn diff(old: &PolicyBundle, new: &PolicyBundle) -> Result<BundleDelta, DeltaError> {
    let (a, b) = (old.body.document(), new.body.document());
    let mut ops = Vec::new();
    let policy_of = |d: &PolicyDocument| d.policy.clone();
    if policy_of(a) != policy_of(b) || a.schema_version != b.schema_version {
        ops.push(Op::PutPolicy(Box::new(b.policy.clone())));
    }
    let (ia, ib) = (index(a), index(b));
    for id in ia.keys().filter(|id| !ib.contains_key(id)) {
        ops.push(Op::RemoveRuleSet(*id));
    }
    for (id, (set, rules)) in &ib {
        let before = ia.get(id);
        if before.is_none_or(|(s, _)| without_rules(s) != without_rules(set)) {
            ops.push(Op::PutRuleSet(Box::new(without_rules(set))));
        }
        let empty = BTreeMap::new();
        let old_rules = before.map_or(&empty, |(_, r)| r);
        for rid in old_rules.keys().filter(|r| !rules.contains_key(r)) {
            ops.push(Op::RemoveRule(*id, *rid));
        }
        for (rid, rule) in rules {
            if old_rules.get(rid) != Some(rule) {
                ops.push(Op::PutRule(*id, Box::new((*rule).clone())));
            }
        }
    }
    library_ops(old.body.libraries(), new.body.libraries(), &mut ops);
    if old.body.source_revisions() != new.body.source_revisions() {
        ops.push(Op::PutSources(new.body.source_revisions().clone()));
    }
    Ok(BundleDelta {
        base_bundle_hash: old.bundle_hash().map_err(DeltaError::Encode)?,
        result_bundle_hash: new.bundle_hash().map_err(DeltaError::Encode)?,
        header: new.header,
        metadata_digest: *new.body.metadata_digest(),
        ops,
    })
}

/// Applies `delta` to the bundle whose canonical bytes are `old_bytes`, as
/// the agent holds them, giving the new bundle and its canonical bytes.
///
/// The base is checked by hashing `old_bytes`, the bytes that were
/// verified, not by encoding a decoded bundle again. The result takes the
/// delta header's schema version, so a delta can cross a schema change.
///
/// # Errors
///
/// [`DeltaError::WrongBase`] unless `old_bytes` hash to the delta's base,
/// [`DeltaError::Decode`] if they are not a bundle within `limits`,
/// [`DeltaError::ResultMismatch`] unless the result hashes to its result,
/// and the errors of operations that do not fit the base.
pub fn apply(
    old_bytes: &[u8],
    delta: &BundleDelta,
    limits: &BundleLimits,
) -> Result<(PolicyBundle, Vec<u8>), DeltaError> {
    if bundle_hash(old_bytes) != delta.base_bundle_hash {
        return Err(DeltaError::WrongBase);
    }
    let old = PolicyBundle::decode(old_bytes, limits).map_err(DeltaError::Decode)?;
    let mut doc = old.body.document().clone();
    let mut libraries = old.body.libraries().to_vec();
    let mut sources = old.body.source_revisions().clone();
    let mut sets: BTreeMap<RuleSetId, RuleSet> =
        doc.rule_sets.drain(..).map(|s| (s.id, s)).collect();
    for op in &delta.ops {
        match op {
            Op::PutPolicy(p) => doc.policy = (**p).clone(),
            Op::RemoveRuleSet(id) => {
                sets.remove(id).ok_or(DeltaError::MissingRuleSet(*id))?;
            }
            Op::PutRuleSet(set) => {
                let rules = sets.remove(&set.id).map(|s| s.rules).unwrap_or_default();
                sets.insert(
                    set.id,
                    RuleSet {
                        rules,
                        ..(**set).clone()
                    },
                );
            }
            Op::RemoveRule(set, rule) => {
                let s = sets.get_mut(set).ok_or(DeltaError::MissingRuleSet(*set))?;
                let before = s.rules.len();
                s.rules.retain(|r| r.id != *rule);
                if s.rules.len() == before {
                    return Err(DeltaError::MissingRule(*rule));
                }
            }
            Op::PutRule(set, rule) => {
                let s = sets.get_mut(set).ok_or(DeltaError::MissingRuleSet(*set))?;
                s.rules.retain(|r| r.id != rule.id);
                s.rules.push((**rule).clone());
            }
            Op::PutLibraries(l) => libraries = l.clone(),
            Op::PutSources(s) => sources = s.clone(),
            Op::PutLibrary(l) => put_library(&mut libraries, (**l).clone()),
            Op::RemoveLibrary(id, v) => {
                let before = libraries.len();
                libraries.retain(|l| (l.id, l.resolved_version) != (*id, *v));
                if libraries.len() == before {
                    return Err(DeltaError::MissingLibrary(*id, *v));
                }
            }
            Op::PatchHashSet(p) => {
                let patched = patch_hash_set(&libraries, p)?;
                put_library(&mut libraries, patched);
            }
        }
    }
    doc.rule_sets = sets.into_values().collect();
    doc.schema_version = delta.header.schema_version;
    let body = Body::with_digest(doc, libraries, sources, delta.metadata_digest)
        .map_err(DeltaError::Encode)?;
    let bundle = PolicyBundle::new(delta.header, body);
    let bytes = bundle.to_bytes().map_err(DeltaError::Encode)?;
    if bundle_hash(&bytes) != delta.result_bundle_hash {
        return Err(DeltaError::ResultMismatch);
    }
    // The result must be a bundle the agent can load under the same limits
    // as the base: a delta that grows it past them is refused here, not
    // left to fail on the next load.
    PolicyBundle::decode(&bytes, limits).map_err(DeltaError::Decode)?;
    Ok((bundle, bytes))
}

/// The library operations from `old` to `new`, both sorted by ID and
/// version: additions and replacements first, each a hash set patch where
/// that is smaller than the set, then removals, so a patch can start from
/// a version the result no longer holds.
fn library_ops(old: &[InlineLibrary], new: &[InlineLibrary], ops: &mut Vec<Op>) {
    let key = |l: &InlineLibrary| (l.id, l.resolved_version);
    for l in new {
        if old.iter().any(|o| o == l) {
            continue;
        }
        match best_patch(old, l) {
            Some(p) => ops.push(Op::PatchHashSet(Box::new(p))),
            None => ops.push(Op::PutLibrary(Box::new(l.clone()))),
        }
    }
    for l in old {
        if !new.iter().any(|n| key(n) == key(l)) {
            ops.push(Op::RemoveLibrary(l.id, l.resolved_version));
        }
    }
}

/// The smallest patch that gives hash set `new` from a version of the same
/// set in `old`, if one is smaller than the set itself.
fn best_patch(old: &[InlineLibrary], new: &InlineLibrary) -> Option<HashSetPatch> {
    let SetContent::HashSet { field, digests } = &new.content else {
        return None;
    };
    old.iter()
        .filter(|o| o.id == new.id)
        .filter_map(|o| match &o.content {
            SetContent::HashSet {
                field: f,
                digests: base,
            } if f == field => {
                let (add, remove) = base.diff(digests);
                Some(HashSetPatch {
                    id: new.id,
                    base_version: o.resolved_version,
                    resolved_version: new.resolved_version,
                    add,
                    remove,
                })
            }
            _ => None,
        })
        .filter(|p| p.add.len() + p.remove.len() < digests.len())
        .min_by_key(|p| (p.add.len() + p.remove.len(), p.base_version))
}

/// Adds `library`, replacing any library of the same ID and version.
fn put_library(libraries: &mut Vec<InlineLibrary>, library: InlineLibrary) {
    libraries.retain(|l| (l.id, l.resolved_version) != (library.id, library.resolved_version));
    libraries.push(library);
}

/// The hash set `p` gives from the version it starts from in `libraries`.
fn patch_hash_set(
    libraries: &[InlineLibrary],
    p: &HashSetPatch,
) -> Result<InlineLibrary, DeltaError> {
    let missing = DeltaError::MissingLibrary(p.id, p.base_version);
    let base = libraries
        .iter()
        .find(|l| (l.id, l.resolved_version) == (p.id, p.base_version))
        .ok_or_else(|| missing.clone())?;
    let SetContent::HashSet { field, digests } = &base.content else {
        return Err(missing);
    };
    Ok(InlineLibrary {
        id: p.id,
        resolved_version: p.resolved_version,
        content: SetContent::HashSet {
            field: *field,
            digests: digests
                .patch(&p.add, &p.remove)
                .map_err(DeltaError::Patch)?,
        },
    })
}

/// Whether to send `delta` rather than the full bundle of `full_len` bytes:
/// the agent's reported bundle hash is the delta's base, and the encoded
/// delta is under half the full size.
#[must_use]
pub fn worth_sending(
    delta: &BundleDelta,
    delta_len: usize,
    full_len: usize,
    agent_hash: &Sha256Digest,
) -> bool {
    *agent_hash == delta.base_bundle_hash && delta_len.saturating_mul(2) < full_len
}

fn bytes32(v: Value) -> Result<Sha256Digest, DeltaError> {
    match v {
        Value::Bytes(b) => b
            .try_into()
            .map_err(|_| DeltaError::Decode(BundleError::Shape("a hash is not 32 bytes"))),
        _ => Err(DeltaError::Decode(BundleError::Shape(
            "a hash is not a byte string",
        ))),
    }
}

fn k(name: &str) -> Value {
    Value::int(super::keys::id(name).unwrap_or(i64::MIN))
}

impl BundleDelta {
    /// The canonical bytes of the delta, for signing (#225) and sending: a
    /// map of the two hashes, the result's header and metadata digest, and
    /// the operations.
    ///
    /// # Errors
    ///
    /// [`DeltaError::Encode`] if it does not encode.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DeltaError> {
        let enc = DeltaError::Encode;
        let value = Value::Map(
            cbor::Map::new(vec![
                (
                    k("base_bundle_hash"),
                    Value::Bytes(self.base_bundle_hash.to_vec()),
                ),
                (
                    k("result_bundle_hash"),
                    Value::Bytes(self.result_bundle_hash.to_vec()),
                ),
                (k("header"), self.header.to_value().map_err(enc)?),
                (
                    k("metadata_digest"),
                    Value::Bytes(self.metadata_digest.to_vec()),
                ),
                (k("ops"), serial::to_value(&self.ops).map_err(enc)?),
            ])
            .map_err(|e| enc(serial::Error::Encode(e)))?,
        );
        cbor::encode(&value).map_err(|e| enc(serial::Error::Encode(e)))
    }

    /// Reads a delta written by [`to_bytes`](Self::to_bytes), strictly. The
    /// result it gives is trusted only after [`apply`] checks its hash.
    ///
    /// # Errors
    ///
    /// [`DeltaError::Decode`] if the bytes are not a canonical delta.
    pub fn from_bytes(bytes: &[u8], limits: &BundleLimits) -> Result<Self, DeltaError> {
        let dec = DeltaError::Decode;
        if bytes.len() > limits.max_bytes {
            return Err(dec(BundleError::TooLarge {
                size: bytes.len(),
                limit: limits.max_bytes,
            }));
        }
        let cbor_limits = Limits {
            max_bytes: limits.max_bytes,
            max_items: limits.max_items,
            ..Limits::DEFAULT
        };
        let Value::Map(m) =
            cbor::decode_with_limits(bytes, &cbor_limits).map_err(|e| dec(BundleError::Cbor(e)))?
        else {
            return Err(dec(BundleError::Shape("a delta is a map")));
        };
        let mut fields: BTreeMap<&'static str, Value> = BTreeMap::new();
        for (key, v) in m.into_entries() {
            let id = key
                .as_i64()
                .ok_or(dec(BundleError::Shape("a delta key is not an integer")))?;
            match super::keys::name(id) {
                Some(name) => {
                    fields.insert(name, v);
                }
                None if id < 0 => {}
                None => return Err(dec(BundleError::UnknownCriticalKey(id))),
            }
        }
        let mut take =
            |name: &'static str| fields.remove(name).ok_or(dec(BundleError::Missing(name)));
        let delta = Self {
            base_bundle_hash: bytes32(take("base_bundle_hash")?)?,
            result_bundle_hash: bytes32(take("result_bundle_hash")?)?,
            header: Header::from_value(take("header")?).map_err(dec)?,
            metadata_digest: bytes32(take("metadata_digest")?)?,
            ops: serial::from_value(take("ops")?).map_err(|e| dec(BundleError::Body(e)))?,
        };
        if let Some(name) = fields.keys().next() {
            return Err(dec(BundleError::Body(serial::Error::Message(format!(
                "`{name}` does not belong in a delta"
            )))));
        }
        Ok(delta)
    }
}

#[cfg(test)]
mod tests;
