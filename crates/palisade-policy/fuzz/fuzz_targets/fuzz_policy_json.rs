//! Fuzzes the strict JSON reader of policy documents, validation and the
//! evaluator build (#30, #25): a policy document arrives from the server or
//! a file, so no input may panic. A document that reads must write back to
//! JSON that reads as the same document, and a document that validates must
//! compile and decide objects with and without facts.
#![no_main]

use libfuzzer_sys::fuzz_target;
use palisade_core::path::VolumeMap;
use palisade_policy::context::EvaluationContext;
use palisade_policy::decision::TraceId;
use palisade_policy::evaluate::{Evaluator, Subject};
use palisade_policy::facts::{ObjectFacts, PathFact, PathVariable, PathVariables};
use palisade_policy::model::{Field, ObjectType, PolicyDocument};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(doc) = PolicyDocument::from_json(text) else {
        return;
    };
    let written = doc.to_json_pretty().unwrap();
    assert_eq!(PolicyDocument::from_json(&written).unwrap(), doc);
    if let Ok(validated) = doc.validate() {
        let evaluator = Evaluator::new(&validated).unwrap();
        let variables =
            PathVariables::new().with(PathVariable::ProgramFiles, &[r"C:\Program Files"]);
        let mut context = EvaluationContext::new();
        context.user.is_admin = Some(false);
        context.user.groups = Some(vec!["S-1-5-32-545".to_owned()]);
        // No facts, and facts that rules in the seed fixtures test.
        let known = ObjectFacts::new()
            .with(Field::HashSha256, "a".repeat(64))
            .with(Field::MetaProductName, "Example Suite")
            .with(Field::MetaFileVersion, "10.0.1.0")
            .with_path(
                PathFact::new(r"C:\Program Files\Example\app.exe", &VolumeMap::new())
                    .with_user_writable(false)
                .with_volume(palisade_policy::unknown::VolumeKind::Fixed),
            )
            .with_signers(Vec::new());
        for facts in [ObjectFacts::new(), known] {
            for object_type in [
                ObjectType::Executable,
                ObjectType::Library,
                ObjectType::Driver,
            ] {
                let _ = evaluator.evaluate(
                    &Subject {
                        object_type,
                        facts: &facts,
                        variables: &variables,
                        context: &context,
                    },
                    TraceId([0; 16]),
                );
            }
        }
    }
});
