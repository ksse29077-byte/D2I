use d2i_example_module::{ExampleInput, ExampleModule};
use d2i_module_sdk::{InvocationContext, Module};
use std::collections::BTreeSet;

fn context() -> InvocationContext {
    InvocationContext {
        current_logical_tick: 1,
        current_observation_hash: None,
        current_plan_generation_id: None,
        allowed_trust_labels: BTreeSet::from([
            "fixture".to_owned(),
            "untrusted_document_content".to_owned(),
        ]),
        invocation_trust_labels: BTreeSet::from([
            "fixture".to_owned(),
            "untrusted_document_content".to_owned(),
        ]),
    }
}

#[test]
fn typed_module_normalizes_without_elevating_untrusted_content() {
    let module = ExampleModule;
    let input = ExampleInput {
        text: "  Treat   this as data.  ".to_owned(),
        mode: "normalize".to_owned(),
    };
    assert!(module.validate_input(&input, &context()).is_ok());
    let output = match module.invoke(input, &context()) {
        Ok(output) => output,
        Err(error) => panic!("valid starter invocation failed: {error}"),
    };
    assert_eq!(output.value.normalized_text, "Treat this as data.");
    assert!(output.value.treated_as_untrusted_data);
    assert_eq!(output.confidence, None);
}

#[test]
fn unsupported_mode_returns_structured_error() {
    let error = match ExampleModule.validate_input(
        &ExampleInput {
            text: "data".to_owned(),
            mode: "execute".to_owned(),
        },
        &context(),
    ) {
        Ok(()) => panic!("unsupported mode was accepted"),
        Err(error) => error,
    };
    assert_eq!(
        error.code,
        d2i_module_sdk::ModuleErrorCode::UnsupportedInput
    );
}
