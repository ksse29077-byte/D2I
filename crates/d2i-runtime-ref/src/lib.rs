//! Deterministic, offline Rust reference runtime for D2I packages.

pub mod cli;
mod executors;
mod package;
mod scheduler;

pub use package::{ReferencePackageLoader, RuntimePackage};
pub use scheduler::Scheduler;

use d2i_core::SkillId;
use d2i_runtime_api::{
    DecisionEnvelope, ExecutorRegistry, PackageLoader, ReplayRecord, ReplayReport, Runtime,
    RuntimeError, TaskContext,
};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

/// Correctness-oriented runtime used as the baseline for future adapters.
pub struct ReferenceRuntime {
    package: Arc<RuntimePackage>,
    scheduler: Scheduler,
}

impl ReferenceRuntime {
    /// Verifies a package, constructs indexes, and binds the built-in MVP executors.
    pub fn load(path: &Path) -> Result<Self, RuntimeError> {
        let package = Arc::new(ReferencePackageLoader.load(path)?);
        let mut registry = ExecutorRegistry::new();
        executors::register_mvp_executors(&mut registry, package.knowledge.clone(), &package)?;
        package::validate_bindings(&package, &registry)?;
        let scheduler = Scheduler::new(package.clone(), Arc::new(registry));
        Ok(Self { package, scheduler })
    }

    /// Executes one skill with a caller-provided request identifier and timeout.
    pub fn run(
        &self,
        skill_id: &str,
        request_id: impl Into<String>,
        request: serde_json::Value,
        timeout: Duration,
    ) -> Result<DecisionEnvelope, RuntimeError> {
        let skill = SkillId::new(skill_id.to_owned())
            .map_err(|error| RuntimeError::UnsupportedSkill(error.to_string()))?;
        let context = TaskContext::new(request_id, skill, timeout)?;
        self.execute(context, request)
    }

    /// Returns metadata for the loaded immutable package.
    #[must_use]
    pub fn package(&self) -> &RuntimePackage {
        &self.package
    }
}

impl Runtime for ReferenceRuntime {
    fn execute(
        &self,
        context: TaskContext,
        request: serde_json::Value,
    ) -> Result<DecisionEnvelope, RuntimeError> {
        self.package
            .validate_request(context.skill_id().as_str(), &request)?;
        self.scheduler.execute(context, request)
    }

    fn replay(&self, record: &ReplayRecord) -> Result<ReplayReport, RuntimeError> {
        if record.envelope.package_content_hash != self.package.summary().package_content_hash {
            return Err(RuntimeError::ReplayMismatch(
                "record package hash does not match the loaded package".to_owned(),
            ));
        }
        if record.envelope.build_id != self.package.summary().build_id {
            return Err(RuntimeError::ReplayMismatch(
                "record build ID does not match the loaded package".to_owned(),
            ));
        }
        let actual = self.run(
            &record.envelope.skill_id,
            record.envelope.request_id.clone(),
            record.request.clone(),
            Duration::from_secs(30),
        )?;
        let expected_decision_hash = record.envelope.decision_hash();
        let actual_decision_hash = actual.decision_hash();
        Ok(ReplayReport {
            matched: expected_decision_hash == actual_decision_hash,
            expected_decision_hash,
            actual_decision_hash,
            envelope: actual,
        })
    }
}
