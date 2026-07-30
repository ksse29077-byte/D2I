//! Copyable starter module demonstrating the Cognitive Module SDK.

use d2i_module_sdk::{
    canonical_sha256, ConfidenceSemantics, InvocationContext, Module, ModuleCapability,
    ModuleCategory, ModuleError, ModuleErrorCode, ModuleMetadata, ModuleOutput, ModuleProvenance,
    NetworkRequirement, SelfCheck, UntrustedContentGuard,
};
use serde::{Deserialize, Serialize};

/// Template module identifier.
pub const MODULE_ID: &str = "example-module";
/// Template capability identifier.
pub const CAPABILITY_ID: &str = "example.normalize-text";

/// Example typed input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExampleInput {
    pub text: String,
    pub mode: String,
}

/// Example typed output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExampleOutput {
    pub normalized_text: String,
    pub treated_as_untrusted_data: bool,
}

/// Pure deterministic starter module.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExampleModule;

impl Module for ExampleModule {
    type Input = ExampleInput;
    type Output = ExampleOutput;

    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata {
            module_id: MODULE_ID.to_owned(),
            module_version: "1.0.0".to_owned(),
            build_id: "example-module-v1".to_owned(),
        }
    }

    fn capabilities(&self) -> Vec<ModuleCapability> {
        vec![ModuleCapability {
            capability_id: CAPABILITY_ID.to_owned(),
            capability_version: "1.0.0".to_owned(),
            category: ModuleCategory("generic_transformation".to_owned()),
            supported_input_kinds: vec!["example-input-v1".to_owned()],
            supported_output_kinds: vec!["example-output-v1".to_owned()],
            supported_risk_classes: vec!["read_only".to_owned()],
            deterministic: true,
            side_effect: false,
            network_requirement: NetworkRequirement::Denied,
            streaming: false,
            confidence_semantics: ConfidenceSemantics::NotApplicable,
        }]
    }

    fn validate_input(
        &self,
        input: &Self::Input,
        _context: &InvocationContext,
    ) -> Result<(), ModuleError> {
        if input.text.is_empty() || input.text.len() > 16 * 1024 {
            return Err(ModuleError::new(
                ModuleErrorCode::InvalidInput,
                "text must be nonempty and at most 16 KiB",
            ));
        }
        if input.mode != "normalize" {
            return Err(ModuleError::new(
                ModuleErrorCode::UnsupportedInput,
                "only normalize mode is supported",
            ));
        }
        Ok(())
    }

    fn invoke(
        &self,
        input: Self::Input,
        context: &InvocationContext,
    ) -> Result<ModuleOutput<Self::Output>, ModuleError> {
        let source_hash = canonical_sha256(&input)?;
        let guard = UntrustedContentGuard::from_labels(&context.invocation_trust_labels);
        let normalized_text = input.text.split_whitespace().collect::<Vec<_>>().join(" ");
        let mut output = ModuleOutput::new(
            ExampleOutput {
                normalized_text,
                treated_as_untrusted_data: guard.contains_untrusted_content(),
            },
            ModuleProvenance {
                source_id: "example-input".to_owned(),
                source_sha256: source_hash,
                producer: MODULE_ID.to_owned(),
            },
        );
        output.logical_operations = 1;
        output.logical_elapsed_ticks = 1;
        if guard.contains_untrusted_content() {
            output
                .warnings
                .push("input was transformed as data without instruction authority".to_owned());
        }
        Ok(output)
    }

    fn self_check(&self) -> SelfCheck {
        SelfCheck {
            healthy: true,
            details: vec!["starter module ready".to_owned()],
        }
    }
}
