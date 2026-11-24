//! Fuzzes the strict JSON reader of policy documents, validation and the
//! evaluator build (#30, #25): a policy document arrives from the server or
//! a file, so no input may panic. A document that reads must write back to
//! JSON that reads as the same document, and a document that validates must
//! compile and evaluate.
#![no_main]

use libfuzzer_sys::fuzz_target;
use palisade_policy::context::EvaluationContext;
use palisade_policy::decision::TraceId;
use palisade_policy::evaluate::{Evaluator, Subject};
use palisade_policy::facts::{ObjectFacts, PathVariables};
use palisade_policy::model::{ObjectType, PolicyDocument};

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
        let (facts, variables, context) = (
            ObjectFacts::new(),
            PathVariables::new(),
            EvaluationContext::new(),
        );
        let _ = evaluator.evaluate(
            &Subject {
                object_type: ObjectType::Executable,
                facts: &facts,
                variables: &variables,
                context: &context,
            },
            TraceId([0; 16]),
        );
    }
});
