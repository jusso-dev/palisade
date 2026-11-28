//! The reference policy of the performance budget (#42), for the
//! benchmarks and the budget test. Not part of the API.
//!
//! The reference policy has 10,000 rules, plus a hash set of 100,000
//! entries (filed as 4,000 rules of 25 SHA-256 values each, the most a
//! criterion holds), 500 publisher rules, 200 path rules and 50 rules with a
//! regular expression leaf. [`Size::Million`] has a hash set of 1,000,000
//! entries instead: 40,000 rules.
//!
//! The objects it decides are a hash hit, a publisher hit, a path wildcard
//! hit, an unknown object (the implicit deny) and a mandatory deny.

use palisade_core::path::VolumeMap;

use crate::context::EvaluationContext;
use crate::facts::{ObjectFacts, PathFact, SignatureSource, SignerFact, SignerStatus};
use crate::model::{Field, PolicyDocument, PrecedenceModel};
use crate::validate::ValidatedPolicy;

/// The size of the hash set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Size {
    /// 100,000 hashes.
    Reference,
    /// 1,000,000 hashes.
    Million,
}

impl Size {
    const fn hashes(self) -> u32 {
        match self {
            Self::Reference => 100_000,
            Self::Million => 1_000_000,
        }
    }
}

/// The rules of the reference policy besides the hash set.
pub const OTHER_RULES: u32 = 10_000;
/// Publisher rules.
pub const PUBLISHERS: u32 = 500;
/// Path rules.
pub const PATHS: u32 = 200;
/// Rules with a regular expression leaf.
pub const REGEXES: u32 = 50;

/// A rule ID: a UUIDv7 whose sequence part is `n`.
fn id(kind: u16, n: u32) -> String {
    format!(
        "01936b2e-{:04x}-7{:03x}-9f21-{:012x}",
        kind,
        n >> 20,
        u64::from(n & 0xf_ffff)
    )
}

/// The SHA-256 of hash-set entry `n`.
#[must_use]
pub fn hash(n: u32) -> String {
    format!(
        "{:016x}{:048x}",
        0x5ef0_u64 << 48 | u64::from(n),
        u64::from(n)
    )
}

fn crit(field: &str, operator: &str, values: &[String]) -> serde_json::Value {
    serde_json::json!({"criterion": {"field": field, "operator": operator, "values": values}})
}

fn rule(kind: u16, n: u32, tree: serde_json::Value, action: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id(kind, n),
        "name": format!("R{kind}-{n}"),
        "object_types": ["executable", "library", "installer"],
        "match": tree,
        "action": {"type": action},
    })
}

/// The reference policy document, under `model`.
#[must_use]
pub fn document(size: Size, model: PrecedenceModel) -> PolicyDocument {
    let mut rules = Vec::new();
    // The hash set, 25 per rule.
    let per = 25;
    for r in 0..size.hashes() / per {
        let values: Vec<String> = (0..per).map(|k| hash(r * per + k)).collect();
        rules.push(rule(1, r, crit("hash.sha256", "equals", &values), "allow"));
    }
    // Publishers: a publisher, some with a product name.
    for n in 0..PUBLISHERS {
        let tree = if n % 2 == 0 {
            crit("signer.publisher", "equals", &[format!("Publisher {n}")])
        } else {
            serde_json::json!({"all": [
                crit("signer.publisher", "equals", &[format!("Publisher {n}")]),
                crit("meta.product_name", "equals", &[format!("Product {n}")]),
            ]})
        };
        rules.push(rule(2, n, tree, "allow"));
    }
    // Paths: folders and wildcards under program files, half denies.
    for n in 0..PATHS {
        let tree = if n % 2 == 0 {
            crit(
                "path.directory",
                "starts_with",
                &[format!(r"C:\Program Files\Vendor {n}")],
            )
        } else {
            crit(
                "path.full",
                "wildcard",
                &[format!(r"C:\Program Files\Vendor {n}\*\*.exe")],
            )
        };
        rules.push(rule(3, n, tree, if n % 4 == 3 { "deny" } else { "allow" }));
    }
    // Regular expressions on a publisher's product: anchored by the
    // publisher, so they are candidates only for that publisher.
    for n in 0..REGEXES {
        rules.push(rule(
            4,
            n,
            serde_json::json!({"all": [
                crit("signer.publisher", "equals", &[format!("Publisher {n}")]),
                crit("meta.original_filename", "regex", &[format!("tool{n}[0-9]*\\.exe")]),
            ]}),
            "audit",
        ));
    }
    // The rest: single hashes, file names with a publisher, and SHA-1
    // denies, up to the reference count.
    let rest = OTHER_RULES - PUBLISHERS - PATHS - REGEXES;
    for n in 0..rest {
        let tree = match n % 3 {
            0 => crit(
                "hash.sha256",
                "equals",
                &[format!("{:064x}", 0xabcd_0000_u64 + u64::from(n))],
            ),
            1 => serde_json::json!({"all": [
                crit("signer.publisher", "equals", &[format!("Publisher {}", n % PUBLISHERS)]),
                crit("path.file_name", "equals", &[format!("app{n}.exe")]),
            ]}),
            _ => crit("hash.sha1", "equals", &[format!("{:040x}", u64::from(n))]),
        };
        let action = if n % 3 == 2 { "deny" } else { "allow" };
        rules.push(rule(5, n, tree, action));
    }
    for (i, r) in rules.iter_mut().enumerate() {
        let i = u32::try_from(i).unwrap_or(u32::MAX);
        if let Some(r) = r.as_object_mut() {
            r.insert("order".into(), (200_000 + i % 700_000).into());
            r.insert("priority".into(), i.into());
        }
    }
    let mandatory = vec![rule(
        6,
        0,
        crit("hash.sha256", "equals", &[MANDATORY.to_owned()]),
        "deny",
    )];
    let model_name = match model {
        PrecedenceModel::DenyWins => "deny_wins",
        PrecedenceModel::AllowWins => "allow_wins",
        PrecedenceModel::Specificity => "specificity",
        PrecedenceModel::FirstMatch => "first_match",
        PrecedenceModel::Priority => "priority",
    };
    let json = serde_json::json!({
        "schema_version": "1.0.0",
        "policy": {
            "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f",
            "name": "Reference",
            "revision": 1,
            "mode": "enforce",
            "precedence_model": model_name,
            "rule_sets": [
                "01936b2e-8c4a-7b3d-9f21-0a1b2c3d0001",
                "01936b2e-8c4a-7b3d-9f21-0a1b2c3d0002"
            ],
        },
        "rule_sets": [
            {
                "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d0001",
                "name": "Reference",
                "kind": "mixed",
                "rules": rules,
            },
            {
                "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d0002",
                "name": "Mandatory",
                "kind": "blocklist",
                "mandatory": true,
                "rules": mandatory,
            }
        ],
    });
    match serde_json::from_value(json) {
        Ok(doc) => doc,
        Err(e) => panic!("the reference policy is not a document: {e}"),
    }
}

/// The reference policy, validated.
///
/// # Panics
///
/// If it does not validate, which a test checks.
#[must_use]
pub fn policy(size: Size, model: PrecedenceModel) -> ValidatedPolicy {
    match document(size, model).validate() {
        Ok(p) => p,
        Err(e) => panic!("the reference policy does not validate: {e:?}"),
    }
}

/// The reference policy compiled into bundle bytes (#43), as an agent
/// receives it, with no library sets.
///
/// # Panics
///
/// If it does not compile, which a test checks.
#[must_use]
pub fn bundle(size: Size, model: PrecedenceModel) -> Vec<u8> {
    use crate::bundle::{BundleLimits, Header, Source, SourceRevisions, Target, TargetScope};
    let policy = policy(size, model);
    let catalogue = match crate::library::Catalogue::new(Vec::new()) {
        Ok(c) => c,
        Err(e) => panic!("an empty catalogue: {e:?}"),
    };
    let id = |n: u8| {
        let mut b = [0u8; 16];
        b[6] = 0x70;
        b[8] = 0x80;
        b[15] = n;
        palisade_core::Uuid7::from_bytes(b)
    };
    let (Some(tenant), Some(group)) = (id(1), id(2)) else {
        panic!("not UUIDv7s");
    };
    let p = &policy.document().policy;
    let source = Source {
        policy: &policy,
        catalogue: &catalogue,
        from: crate::library::Visibility::Global,
        sources: SourceRevisions {
            policies: vec![(p.id, p.revision)],
            libraries: Vec::new(),
        },
        facts: crate::analysis::Facts::default(),
        admin: None,
    };
    let header = Header::new(
        Target {
            tenant,
            scope: TargetScope::Group(group),
        },
        1,
        1_764_201_600_000_000,
    );
    match crate::bundle::compile(&source, header, &BundleLimits::DEFAULT) {
        Ok(c) => c.bytes,
        Err(e) => panic!("the reference policy does not compile into a bundle: {e}"),
    }
}

/// The SHA-256 the mandatory deny blocks.
pub const MANDATORY: &str = "dead00000000000000000000000000000000000000000000000000000000beef";

/// The objects the budget measures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Case {
    /// An entry of the hash set.
    HashHit,
    /// A publisher rule's publisher and product.
    PublisherHit,
    /// A path wildcard's folder.
    PathWildcard,
    /// Nothing matches: the implicit deny.
    UnknownBlock,
    /// The mandatory deny's hash.
    MandatoryDeny,
}

impl Case {
    /// Every case.
    pub const ALL: [Self; 5] = [
        Self::HashHit,
        Self::PublisherHit,
        Self::PathWildcard,
        Self::UnknownBlock,
        Self::MandatoryDeny,
    ];

    /// The benchmark name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::HashHit => "eval_hash_hit",
            Self::PublisherHit => "eval_publisher_hit",
            Self::PathWildcard => "eval_path_wildcard",
            Self::UnknownBlock => "eval_unknown_block",
            Self::MandatoryDeny => "eval_mandatory_deny",
        }
    }

    /// The facts of the object, with every class computed. `i` varies the
    /// object, so a run does not decide one object only.
    #[must_use]
    pub fn facts(self, i: u32, size: Size) -> ObjectFacts {
        let volumes = VolumeMap::new();
        let (sha, path, signer) = match self {
            Self::HashHit => (
                hash(i.wrapping_mul(7919) % size.hashes()),
                r"C:\Users\u\Downloads\setup.exe".to_owned(),
                None,
            ),
            Self::PublisherHit => {
                let n = (i % (PUBLISHERS / 2)) * 2 + 1;
                (
                    format!("{:064x}", 0xffff_0000_u64 + u64::from(i)),
                    r"C:\Apps\x\tool.exe".to_owned(),
                    Some((format!("Publisher {n}"), format!("Product {n}"))),
                )
            }
            Self::PathWildcard => {
                // A wildcard allow: odd rule numbers are wildcards, and
                // those that are 3 modulo 4 deny.
                let n = (i % (PATHS / 4)) * 4 + 1;
                (
                    format!("{:064x}", 0xeeee_0000_u64 + u64::from(i)),
                    format!(r"C:\Program Files\Vendor {n}\bin\app.exe"),
                    None,
                )
            }
            Self::UnknownBlock => (
                format!("{:064x}", 0xdddd_0000_u64 + u64::from(i)),
                format!(r"C:\Users\u\AppData\Local\Temp\{i}\x.exe"),
                Some(("Unknown Signer".to_owned(), "Unknown".to_owned())),
            ),
            Self::MandatoryDeny => (
                MANDATORY.to_owned(),
                r"C:\Program Files\Vendor 1\bin\a.exe".to_owned(),
                None,
            ),
        };
        let mut facts = ObjectFacts::new()
            .with(Field::HashSha256, sha)
            // No SHA-1 deny of the policy names this.
            .with(
                Field::HashSha1,
                format!("{:040x}", 0xf000_0000_u64 + u64::from(i)),
            )
            .with(Field::MetaOriginalFilename, "tool.exe")
            .with_path(PathFact::new(&path, &volumes).with_user_writable(false));
        let signers = match signer {
            Some((publisher, product)) => {
                facts.set(Field::MetaProductName, product);
                vec![SignerFact {
                    status: SignerStatus::Valid,
                    source: SignatureSource::Embedded,
                    publisher: Some(publisher),
                    issuer: Some("Example CA".to_owned()),
                    leaf_thumbprint_sha256: Some("ab".repeat(32)),
                    details: Default::default(),
                }]
            }
            None => Vec::new(),
        };
        facts.with_signers(signers)
    }

    /// The outcome the case must have, under `deny_wins`.
    #[must_use]
    pub const fn expected(self) -> crate::decision::Outcome {
        use crate::decision::Outcome;
        match self {
            Self::HashHit | Self::PublisherHit | Self::PathWildcard => Outcome::Allowed,
            Self::UnknownBlock | Self::MandatoryDeny => Outcome::Blocked,
        }
    }
}

/// An empty context.
#[must_use]
pub fn context() -> EvaluationContext {
    EvaluationContext::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evaluate::{Evaluator, Subject};
    use crate::facts::PathVariables;
    use crate::model::ObjectType;

    #[test]
    fn the_reference_policy_validates_and_decides_each_case() {
        let p = policy(Size::Reference, PrecedenceModel::DenyWins);
        let rules: usize = p.document().rule_sets.iter().map(|s| s.rules.len()).sum();
        assert_eq!(rules, 4_000 + 10_000 + 1);
        let e = Evaluator::new(&p).unwrap();
        let stats = e.index_stats();
        assert_eq!(stats.always_eval, 0, "every reference rule is indexed");
        let v = PathVariables::new();
        let c = context();
        for case in Case::ALL {
            for i in [0, 1, 99] {
                let f = case.facts(i, Size::Reference);
                let s = Subject {
                    object_type: ObjectType::Executable,
                    facts: &f,
                    variables: &v,
                    context: &c,
                };
                let d = e.evaluate(&s, crate::decision::TraceId([0; 16]));
                assert_eq!(d.outcome(), case.expected(), "{case:?} {i}");
                assert_eq!(
                    d.matched_rule().is_some(),
                    case != Case::UnknownBlock,
                    "{case:?} {i}"
                );
                // The linear scan agrees.
                let linear = e.evaluate_linear(&s, crate::decision::TraceId([0; 16]));
                assert_eq!(d, linear, "{case:?} {i}");
            }
        }
    }
}
