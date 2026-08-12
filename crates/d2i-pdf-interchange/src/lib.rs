//! PDF finalization contracts that preserve editable source authority and verify fixed projections.

mod contracts;

pub use contracts::*;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

pub const PDF_INTERCHANGE_SCHEMA_VERSION: u32 = 1;
pub const ZERO_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";
pub const MAX_PDF_JSON_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_PDF_PAGES: u32 = 500;
pub const MAX_EXTERNAL_PDF_PAGES: u32 = 100;
pub const MAX_PDF_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_EXTERNAL_PDF_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_RENDER_PIXELS: u64 = 500_000_000;
pub const REQUIRED_REPLAY_SCENARIOS: u32 = 128;
pub const REQUIRED_REPLAY_RUNS: u32 = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdfRecoveryStageV1 {
    BeforeActivation,
    OfficeOpenBeforeExport,
    ExportOutcomeUnknown,
    PdfObserved,
    PdfHashDurable,
    ExportReceiptDurable,
    PartialRenderDurable,
    RenderComplete,
    VerificationDurable,
    PairDurable,
    SealDurable,
    ManifestDurable,
    SourceGenerationChanged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdfRecoveryActionV1 {
    NoSideEffect,
    CloseOfficeWithoutExport,
    InspectAmbiguousExport,
    RecoverExistingPdf,
    ResumeRender,
    ResumeRemainingRenderPages,
    RecomputeVisualReport,
    RepairPairMetadata,
    RepairFinalizationSeal,
    RepairSubmissionManifest,
    RepairCaseProjection,
    ProhibitSeal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PdfRecoveryEvidenceV1 {
    pub stage: PdfRecoveryStageV1,
    pub exact_pdf_hash_available: bool,
    pub render_checkpoint_verified: bool,
    pub source_generation_matches: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PdfRecoveryDecisionV1 {
    pub action: PdfRecoveryActionV1,
    pub blind_export_replay_allowed: bool,
    pub inspect_existing_pdf: bool,
    pub resume_render: bool,
    pub metadata_only: bool,
    pub seal_allowed: bool,
}

/// Selects the only recovery action allowed by one durable finalization state.
pub fn decide_pdf_recovery_v1(
    evidence: PdfRecoveryEvidenceV1,
) -> Result<PdfRecoveryDecisionV1, PdfInterchangeError> {
    use PdfRecoveryActionV1 as Action;
    use PdfRecoveryStageV1 as Stage;

    let requires_pdf_hash = matches!(
        evidence.stage,
        Stage::PdfObserved
            | Stage::PdfHashDurable
            | Stage::ExportReceiptDurable
            | Stage::PartialRenderDurable
            | Stage::RenderComplete
            | Stage::VerificationDurable
            | Stage::PairDurable
            | Stage::SealDurable
            | Stage::ManifestDurable
            | Stage::SourceGenerationChanged
    );
    if requires_pdf_hash && !evidence.exact_pdf_hash_available {
        return Err(integrity("PDF recovery requires an exact durable PDF hash"));
    }
    if evidence.stage == Stage::PartialRenderDurable && !evidence.render_checkpoint_verified {
        return Err(integrity(
            "partial PDF render recovery requires a verified page checkpoint",
        ));
    }
    if evidence.stage == Stage::SourceGenerationChanged {
        if evidence.source_generation_matches {
            return Err(integrity(
                "source-change recovery requires a changed source generation",
            ));
        }
    } else if !evidence.source_generation_matches {
        return Err(integrity(
            "PDF recovery evidence is stale for the source generation",
        ));
    }

    let (action, inspect_existing_pdf, resume_render, metadata_only, seal_allowed) = match evidence
        .stage
    {
        Stage::BeforeActivation => (Action::NoSideEffect, false, false, false, false),
        Stage::OfficeOpenBeforeExport => {
            (Action::CloseOfficeWithoutExport, false, false, false, false)
        }
        Stage::ExportOutcomeUnknown => (Action::InspectAmbiguousExport, true, false, false, false),
        Stage::PdfObserved | Stage::PdfHashDurable => {
            (Action::RecoverExistingPdf, true, false, false, false)
        }
        Stage::ExportReceiptDurable => (Action::ResumeRender, true, true, false, false),
        Stage::PartialRenderDurable => {
            (Action::ResumeRemainingRenderPages, true, true, false, false)
        }
        Stage::RenderComplete => (Action::RecomputeVisualReport, true, false, true, false),
        Stage::VerificationDurable => (Action::RepairPairMetadata, true, false, true, false),
        Stage::PairDurable => (Action::RepairFinalizationSeal, true, false, true, true),
        Stage::SealDurable => (Action::RepairSubmissionManifest, true, false, true, true),
        Stage::ManifestDurable => (Action::RepairCaseProjection, true, false, true, true),
        Stage::SourceGenerationChanged => (Action::ProhibitSeal, true, false, true, false),
    };
    Ok(PdfRecoveryDecisionV1 {
        action,
        blind_export_replay_allowed: false,
        inspect_existing_pdf,
        resume_render,
        metadata_only,
        seal_allowed,
    })
}

/// Verifies the closed A-M recovery matrix and returns its exact case count.
pub fn verify_pdf_recovery_matrix_v1() -> Result<u32, PdfInterchangeError> {
    use PdfRecoveryActionV1 as Action;
    use PdfRecoveryStageV1 as Stage;

    let cases = [
        (
            Stage::BeforeActivation,
            false,
            false,
            true,
            PdfRecoveryDecisionV1 {
                action: Action::NoSideEffect,
                blind_export_replay_allowed: false,
                inspect_existing_pdf: false,
                resume_render: false,
                metadata_only: false,
                seal_allowed: false,
            },
        ),
        (
            Stage::OfficeOpenBeforeExport,
            false,
            false,
            true,
            PdfRecoveryDecisionV1 {
                action: Action::CloseOfficeWithoutExport,
                blind_export_replay_allowed: false,
                inspect_existing_pdf: false,
                resume_render: false,
                metadata_only: false,
                seal_allowed: false,
            },
        ),
        (
            Stage::ExportOutcomeUnknown,
            false,
            false,
            true,
            PdfRecoveryDecisionV1 {
                action: Action::InspectAmbiguousExport,
                blind_export_replay_allowed: false,
                inspect_existing_pdf: true,
                resume_render: false,
                metadata_only: false,
                seal_allowed: false,
            },
        ),
        (
            Stage::PdfObserved,
            true,
            false,
            true,
            PdfRecoveryDecisionV1 {
                action: Action::RecoverExistingPdf,
                blind_export_replay_allowed: false,
                inspect_existing_pdf: true,
                resume_render: false,
                metadata_only: false,
                seal_allowed: false,
            },
        ),
        (
            Stage::PdfHashDurable,
            true,
            false,
            true,
            PdfRecoveryDecisionV1 {
                action: Action::RecoverExistingPdf,
                blind_export_replay_allowed: false,
                inspect_existing_pdf: true,
                resume_render: false,
                metadata_only: false,
                seal_allowed: false,
            },
        ),
        (
            Stage::ExportReceiptDurable,
            true,
            false,
            true,
            PdfRecoveryDecisionV1 {
                action: Action::ResumeRender,
                blind_export_replay_allowed: false,
                inspect_existing_pdf: true,
                resume_render: true,
                metadata_only: false,
                seal_allowed: false,
            },
        ),
        (
            Stage::PartialRenderDurable,
            true,
            true,
            true,
            PdfRecoveryDecisionV1 {
                action: Action::ResumeRemainingRenderPages,
                blind_export_replay_allowed: false,
                inspect_existing_pdf: true,
                resume_render: true,
                metadata_only: false,
                seal_allowed: false,
            },
        ),
        (
            Stage::RenderComplete,
            true,
            false,
            true,
            PdfRecoveryDecisionV1 {
                action: Action::RecomputeVisualReport,
                blind_export_replay_allowed: false,
                inspect_existing_pdf: true,
                resume_render: false,
                metadata_only: true,
                seal_allowed: false,
            },
        ),
        (
            Stage::VerificationDurable,
            true,
            false,
            true,
            PdfRecoveryDecisionV1 {
                action: Action::RepairPairMetadata,
                blind_export_replay_allowed: false,
                inspect_existing_pdf: true,
                resume_render: false,
                metadata_only: true,
                seal_allowed: false,
            },
        ),
        (
            Stage::PairDurable,
            true,
            false,
            true,
            PdfRecoveryDecisionV1 {
                action: Action::RepairFinalizationSeal,
                blind_export_replay_allowed: false,
                inspect_existing_pdf: true,
                resume_render: false,
                metadata_only: true,
                seal_allowed: true,
            },
        ),
        (
            Stage::SealDurable,
            true,
            false,
            true,
            PdfRecoveryDecisionV1 {
                action: Action::RepairSubmissionManifest,
                blind_export_replay_allowed: false,
                inspect_existing_pdf: true,
                resume_render: false,
                metadata_only: true,
                seal_allowed: true,
            },
        ),
        (
            Stage::ManifestDurable,
            true,
            false,
            true,
            PdfRecoveryDecisionV1 {
                action: Action::RepairCaseProjection,
                blind_export_replay_allowed: false,
                inspect_existing_pdf: true,
                resume_render: false,
                metadata_only: true,
                seal_allowed: true,
            },
        ),
        (
            Stage::SourceGenerationChanged,
            true,
            false,
            false,
            PdfRecoveryDecisionV1 {
                action: Action::ProhibitSeal,
                blind_export_replay_allowed: false,
                inspect_existing_pdf: true,
                resume_render: false,
                metadata_only: true,
                seal_allowed: false,
            },
        ),
    ];
    for (stage, exact_pdf_hash_available, render_checkpoint_verified, source_matches, expected) in
        cases
    {
        let decision = decide_pdf_recovery_v1(PdfRecoveryEvidenceV1 {
            stage,
            exact_pdf_hash_available,
            render_checkpoint_verified,
            source_generation_matches: source_matches,
        })?;
        if decision != expected {
            return Err(integrity(format!(
                "PDF recovery matrix decision drifted at {stage:?}: actual {decision:?}, expected {expected:?}"
            )));
        }
    }
    u32::try_from(cases.len()).map_err(|error| invalid(format!("recovery case count: {error}")))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PdfInterchangeError {
    Invalid(String),
    Integrity(String),
    AccessDenied(String),
    Resource(String),
    Json(String),
}

impl Display for PdfInterchangeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(formatter, "invalid PDF artifact: {message}"),
            Self::Integrity(message) => write!(formatter, "PDF integrity failure: {message}"),
            Self::AccessDenied(message) => write!(formatter, "PDF access denied: {message}"),
            Self::Resource(message) => write!(formatter, "PDF resource limit: {message}"),
            Self::Json(message) => write!(formatter, "PDF JSON failure: {message}"),
        }
    }
}

impl Error for PdfInterchangeError {}

fn invalid(message: impl Into<String>) -> PdfInterchangeError {
    PdfInterchangeError::Invalid(message.into())
}

fn integrity(message: impl Into<String>) -> PdfInterchangeError {
    PdfInterchangeError::Integrity(message.into())
}

fn validate_bounded<T: Serialize>(value: &T) -> Result<(), PdfInterchangeError> {
    let value = serde_json::to_value(value)
        .map_err(|error| PdfInterchangeError::Json(error.to_string()))?;
    validate_value(&value, 0)?;
    let bytes =
        serde_json::to_vec(&value).map_err(|error| PdfInterchangeError::Json(error.to_string()))?;
    if bytes.len() > MAX_PDF_JSON_BYTES {
        return Err(PdfInterchangeError::Resource(
            "serialized PDF artifact exceeds 8 MiB".to_owned(),
        ));
    }
    Ok(())
}

fn validate_value(value: &Value, depth: usize) -> Result<(), PdfInterchangeError> {
    if depth > 64 {
        return Err(PdfInterchangeError::Resource(
            "PDF artifact nesting exceeds 64 levels".to_owned(),
        ));
    }
    match value {
        Value::Array(values) => {
            if values.len() > 4096 {
                return Err(PdfInterchangeError::Resource(
                    "PDF artifact collection exceeds 4096 entries".to_owned(),
                ));
            }
            for value in values {
                validate_value(value, depth.saturating_add(1))?;
            }
        }
        Value::Object(values) => {
            if values.len() > 256 {
                return Err(PdfInterchangeError::Resource(
                    "PDF artifact object exceeds 256 fields".to_owned(),
                ));
            }
            for value in values.values() {
                validate_value(value, depth.saturating_add(1))?;
            }
        }
        Value::String(value) => {
            if value.len() > 2048 || value.contains('\0') {
                return Err(PdfInterchangeError::Resource(
                    "PDF artifact string contains NUL or exceeds 2048 bytes".to_owned(),
                ));
            }
            let bytes = value.as_bytes();
            let windows_absolute = bytes.len() >= 3
                && bytes[0].is_ascii_alphabetic()
                && bytes[1] == b':'
                && matches!(bytes[2], b'\\' | b'/');
            if windows_absolute || value.starts_with("\\\\") || value.starts_with('/') {
                return Err(PdfInterchangeError::AccessDenied(
                    "PDF artifact contains a raw absolute path".to_owned(),
                ));
            }
            for forbidden in [
                "ShellExecute",
                "SendKeys",
                "Microsoft Print to PDF",
                "CreateObject",
                "javascript:",
                "powershell.exe",
                "cmd.exe /c",
                "FixedFormatExtClassPtr",
                "raw_pdf_bytes",
                "password=",
                "credential=",
            ] {
                if value.contains(forbidden) {
                    return Err(PdfInterchangeError::AccessDenied(format!(
                        "PDF artifact contains forbidden token {forbidden}"
                    )));
                }
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}

/// Computes the canonical D2I SHA-256 identity of a typed PDF contract.
pub fn pdf_canonical_sha256<T: Serialize>(value: &T) -> Result<String, PdfInterchangeError> {
    let value = serde_json::to_value(value)
        .map_err(|error| PdfInterchangeError::Json(error.to_string()))?;
    let bytes =
        serde_json::to_vec(&value).map_err(|error| PdfInterchangeError::Json(error.to_string()))?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn hash_without<T: Serialize>(value: &T, fields: &[&str]) -> Result<String, PdfInterchangeError> {
    let mut value = serde_json::to_value(value)
        .map_err(|error| PdfInterchangeError::Json(error.to_string()))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| invalid("hash target must be an object"))?;
    for field in fields {
        let replacement = if *field == "signature_hex" {
            String::new()
        } else {
            ZERO_HASH.to_owned()
        };
        if object
            .insert((*field).to_owned(), Value::String(replacement))
            .is_none()
        {
            return Err(invalid(format!("hash field {field} is absent")));
        }
    }
    pdf_canonical_sha256(&value)
}

fn validate_hash(value: &str, field: &str) -> Result<(), PdfInterchangeError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(invalid(format!("{field} is not a SHA-256 identity")));
    };
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid(format!("{field} is not a SHA-256 identity")));
    }
    Ok(())
}

fn validate_id(value: &str, field: &str) -> Result<(), PdfInterchangeError> {
    if value.is_empty()
        || value.len() > 512
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')
        })
    {
        return Err(invalid(format!("{field} is not a bounded identifier")));
    }
    Ok(())
}

fn validate_ids(values: &[String], field: &str) -> Result<(), PdfInterchangeError> {
    if values.len() > 4096 {
        return Err(PdfInterchangeError::Resource(format!(
            "{field} exceeds 4096 entries"
        )));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        validate_id(value, field)?;
        if !seen.insert(value) {
            return Err(invalid(format!("{field} contains duplicates")));
        }
    }
    Ok(())
}

macro_rules! impl_sealed {
    ($type:ty, $field:ident) => {
        impl $type {
            pub fn seal(mut self) -> Result<Self, PdfInterchangeError> {
                self.$field = ZERO_HASH.to_owned();
                validate_bounded(&self)?;
                self.$field = hash_without(&self, &[stringify!($field)])?;
                Ok(self)
            }

            pub fn validate(&self) -> Result<(), PdfInterchangeError> {
                validate_hash(&self.$field, stringify!($field))?;
                validate_bounded(self)?;
                if self.$field != hash_without(self, &[stringify!($field)])? {
                    return Err(integrity(concat!(stringify!($type), " hash differs")));
                }
                Ok(())
            }
        }
    };
}

impl_sealed!(PdfFinalizationIntentV1, intent_sha256);
impl_sealed!(PdfExportProfileV1, profile_sha256);
impl_sealed!(PdfExportRequestV1, request_sha256);
impl_sealed!(PdfExportBackendDescriptorV1, descriptor_sha256);
impl_sealed!(PdfExportBindingV1, binding_sha256);
impl_sealed!(PdfExportReceiptV1, receipt_sha256);
impl_sealed!(PdfPageSnapshotV1, page_sha256);
impl_sealed!(PdfDocumentSnapshotV1, snapshot_sha256);
impl_sealed!(PdfRenderRequestV1, request_sha256);
impl_sealed!(PdfRenderResultV1, result_sha256);
impl_sealed!(PdfVisualFingerprintV1, fingerprint_sha256);
impl_sealed!(PdfVisualFidelityReportV1, report_sha256);
impl_sealed!(PdfGeometryVerificationV1, verification_sha256);
impl_sealed!(PdfPostExportVerificationV1, verification_sha256);
impl_sealed!(FinalArtifactPairV1, pair_sha256);
impl_sealed!(DocumentInterchangeManifestV1, manifest_sha256);
impl_sealed!(SubmissionArtifactManifestV1, manifest_sha256);
impl_sealed!(PdfWorkReplayReportV1, report_sha256);
impl_sealed!(PdfWorkCompletionReportV1, finished_sha256);

impl PdfInterchangeProfileV1 {
    /// Returns the fixed profile identifier used in audit and manifests.
    pub const fn profile_id(self) -> &'static str {
        match self {
            Self::SubmissionStatic => "submission_static",
            Self::InternalReview => "internal_review",
            Self::ArchivePdfaRequested => "archive_pdfa_requested",
        }
    }
}

impl PdfExportProfileV1 {
    pub fn validate_profile(&self) -> Result<(), PdfInterchangeError> {
        self.validate()?;
        if self.schema_version != 1
            || self.quality_id != "print"
            || self.optimization_id != "print"
            || self.metadata_policy_id != "exclude_source_properties"
            || self.hidden_content_policy_id != "exclude"
            || self.external_link_policy_id != "reject"
            || self.font_policy_id != "require_installed_no_bitmap_fallback"
            || (self.profile == PdfInterchangeProfileV1::ArchivePdfaRequested)
                != self.pdfa_requested
        {
            return Err(invalid("PDF export profile policy differs"));
        }
        Ok(())
    }
}

impl PdfExportRequestV1 {
    /// Validates source freshness, TTL, and a closed source/backend compatibility contract.
    pub fn validate_preflight(&self, now_unix_ms: u64) -> Result<(), PdfInterchangeError> {
        self.validate()?;
        if self.schema_version != 1
            || self.source_generation == 0
            || self.issued_at_unix_ms == 0
            || self.deadline_unix_ms <= self.issued_at_unix_ms
            || self.deadline_unix_ms.saturating_sub(self.issued_at_unix_ms) > 300_000
            || now_unix_ms < self.issued_at_unix_ms
            || now_unix_ms >= self.deadline_unix_ms
        {
            return Err(PdfInterchangeError::AccessDenied(
                "PDF export request version, generation, or TTL differs".to_owned(),
            ));
        }
        for id in [
            &self.request_id,
            &self.organization_id,
            &self.case_id,
            &self.role_id,
            &self.workspace_id,
            &self.source_artifact_id,
            &self.output_artifact_id,
        ] {
            validate_id(id, "PDF export identity")?;
        }
        for hash in [
            &self.expected_source_sha256,
            &self.expected_source_snapshot_sha256,
            &self.expected_source_verification_sha256,
            &self.expected_source_quality_sha256,
            &self.expected_application_state_sha256,
            &self.finalization_intent_sha256,
            &self.export_profile_sha256,
            &self.backend_approval_sha256,
        ] {
            validate_hash(hash, "PDF export binding")?;
        }
        validate_ids(&self.approved_sheet_ids, "approved sheet identity")?;
        if let Some(value) = &self.expected_design_quality_ref {
            validate_id(value, "design quality reference")?;
        }
        match self.source_format {
            PdfSourceFormatV1::Docx | PdfSourceFormatV1::Xlsx | PdfSourceFormatV1::Pptx => Ok(()),
            PdfSourceFormatV1::Hwpx => Err(PdfInterchangeError::AccessDenied(
                "requires_licensed_hancom_render_backend".to_owned(),
            )),
            PdfSourceFormatV1::ExternalPdf => Err(PdfInterchangeError::AccessDenied(
                "external PDF is render-only and cannot enter export finalization".to_owned(),
            )),
        }
    }
}

impl PdfRenderRequestV1 {
    /// Validates stricter limits for untrusted external PDFs.
    pub fn validate_limits(
        &self,
        pdf_bytes: u64,
        now_unix_ms: u64,
    ) -> Result<(), PdfInterchangeError> {
        self.validate()?;
        let page_limit = if self.external_untrusted {
            MAX_EXTERNAL_PDF_PAGES
        } else {
            MAX_PDF_PAGES
        };
        let byte_limit = if self.external_untrusted {
            MAX_EXTERNAL_PDF_BYTES
        } else {
            MAX_PDF_BYTES
        };
        if self.schema_version != 1
            || self.maximum_pages == 0
            || self.maximum_pages > page_limit
            || self.maximum_pdf_bytes == 0
            || self.maximum_pdf_bytes > byte_limit
            || pdf_bytes > self.maximum_pdf_bytes
            || self.maximum_total_pixels == 0
            || self.maximum_total_pixels > MAX_RENDER_PIXELS
            || self.maximum_page_width_millipoints == 0
            || self.maximum_page_height_millipoints == 0
            || self.maximum_output_png_bytes == 0
            || self.maximum_output_png_bytes > 128 * 1024 * 1024
            || self.maximum_worker_memory_bytes < 64 * 1024 * 1024
            || self.maximum_worker_memory_bytes > 2 * 1024 * 1024 * 1024
            || self.maximum_page_render_milliseconds == 0
            || self.maximum_page_render_milliseconds > 60_000
            || self.maximum_total_render_milliseconds == 0
            || self.maximum_total_render_milliseconds > 300_000
            || !(1_600..=2_400).contains(&self.destination_width_pixels)
            || self.issued_at_unix_ms == 0
            || self.deadline_unix_ms <= self.issued_at_unix_ms
            || self.deadline_unix_ms.saturating_sub(self.issued_at_unix_ms)
                > self.maximum_total_render_milliseconds
            || now_unix_ms < self.issued_at_unix_ms
            || now_unix_ms >= self.deadline_unix_ms
        {
            return Err(PdfInterchangeError::Resource(
                "PDF render request exceeds its bounded profile".to_owned(),
            ));
        }
        validate_hash(&self.expected_pdf_sha256, "render PDF hash")
    }
}

impl FinalArtifactPairV1 {
    /// Enforces immutable pair state and exact readiness gates.
    pub fn validate_finalization(
        &self,
        verification: &PdfPostExportVerificationV1,
    ) -> Result<(), PdfInterchangeError> {
        self.validate()?;
        verification.validate()?;
        if self.post_export_verification_sha256 != verification.verification_sha256 {
            return Err(integrity(
                "final artifact pair post-export verification binding differs",
            ));
        }
        let ready = self.state == FinalArtifactPairStateV1::Finalized
            && verification.verified
            && verification.source_lineage_verified
            && verification.security_verified
            && verification.independent_load_verified
            && verification.independent_render_verified
            && verification.failure_code == PdfFailureCodeV1::None;
        if self.ready_for_submission != ready {
            return Err(integrity(
                "ready_for_submission differs from fixed finalization gates",
            ));
        }
        Ok(())
    }

    /// Returns a new immutable projection marking this pair superseded by a source change.
    pub fn supersede(mut self, current_source_sha256: &str) -> Result<Self, PdfInterchangeError> {
        self.validate()?;
        validate_hash(current_source_sha256, "current source hash")?;
        if self.state != FinalArtifactPairStateV1::Finalized
            || current_source_sha256 == self.source_artifact_sha256
        {
            return Err(invalid(
                "only a changed finalized source may supersede a pair",
            ));
        }
        self.state = FinalArtifactPairStateV1::Superseded;
        self.ready_for_submission = false;
        self.pair_sha256 = ZERO_HASH.to_owned();
        self.seal()
    }
}

impl PdfWorkReplayReportV1 {
    pub fn validate_gate(&self) -> Result<(), PdfInterchangeError> {
        self.validate()?;
        let mismatches = self
            .export_selection_mismatch_count
            .saturating_add(self.geometry_mismatch_count)
            .saturating_add(self.lineage_mismatch_count)
            .saturating_add(self.manifest_mismatch_count)
            .saturating_add(self.stale_acceptance_count)
            .saturating_add(self.blind_replay_count);
        if self.schema_version != 1
            || self.scenario_count != REQUIRED_REPLAY_SCENARIOS
            || self.runs_per_scenario != REQUIRED_REPLAY_RUNS
            || mismatches != 0
        {
            return Err(integrity("PDF replay gate differs"));
        }
        Ok(())
    }
}

impl PdfWorkCompletionReportV1 {
    pub fn validate_gate(&self) -> Result<(), PdfInterchangeError> {
        self.validate()?;
        for hash in [
            &self.source_tree_sha256,
            &self.predecessor_finished_sha256,
            &self.replay_report_sha256,
            &self.protected_audit_terminal_sha256,
        ] {
            validate_hash(hash, "completion hash")?;
        }
        let gates = self.schema_version == 1
            && self.word_pdf_exports >= 2
            && self.excel_pdf_exports >= 2
            && self.powerpoint_pdf_exports >= 2
            && self.pdf_load_count >= 6
            && self.rendered_page_count >= 15
            && self.powerpoint_fidelity_comparisons >= 5
            && self.external_pdf_render_only_cases >= 1
            && self.external_pdf_malformed_rejections >= 1
            && self.external_pdf_password_rejections >= 1
            && self.external_pdf_oversize_rejections >= 1
            && self.actual_qwen_invocation_count >= 1
            && self.final_artifact_pair_count >= 6
            && self.submission_manifest_count >= 6
            && self.stale_pair_count >= 1
            && self.superseded_pair_count >= 1
            && self.pdfa_requested_cases >= 1
            && self.pdfa_exporter_requested_cases >= 1
            && self.pdfa_external_conformance_verified_cases == 0
            && self.hwpx_pdf_export_status
                == PdfVerificationStatusV1::RequiresLicensedHancomRenderBackend
            && self.crash_windows_verified >= 13
            && self.performance.pdf_load_microseconds > 0
            && self.performance.render_microseconds > 0
            && self.performance.peak_export_worker_memory_bytes > 0
            && self.performance.peak_render_worker_memory_bytes > 0
            && self.performance.peak_model_worker_memory_bytes > 0
            && self.security == PdfSecurityMetricsV1::default()
            && self.residual == PdfResidualMetricsV1::default()
            && self.pdf_interchange_evidence
            && self.word_pdf_export_evidence
            && self.excel_pdf_export_evidence
            && self.powerpoint_pdf_export_evidence
            && self.independent_pdf_render_evidence
            && self.powerpoint_visual_fidelity_evidence
            && self.source_pdf_lineage_evidence
            && self.submission_manifest_evidence
            && self.external_pdf_render_only_evidence
            && self.office450_lineage_evidence
            && self.track_o_office500_evidence
            && self.routine_human_touch_zero
            && self.complete;
        if !gates {
            return Err(integrity("OFFICE-500 Completion gates are incomplete"));
        }
        Ok(())
    }
}

impl PdfExportBackendApprovalV1 {
    pub fn sign(mut self, key: &SigningKey) -> Result<Self, PdfInterchangeError> {
        self.signature_hex = "00".repeat(64);
        self.approval_sha256 = ZERO_HASH.to_owned();
        self.validate_content()?;
        let payload = signature_payload(&self, &["signature_hex", "approval_sha256"])?;
        self.signature_hex = hex_encode(&key.sign(&payload).to_bytes());
        self.approval_sha256 = hash_without(&self, &["approval_sha256"])?;
        Ok(self)
    }

    pub fn verify(&self, key: &VerifyingKey, now_unix_ms: u64) -> Result<(), PdfInterchangeError> {
        self.validate_content()?;
        if now_unix_ms < self.issued_at_unix_ms || now_unix_ms >= self.expires_at_unix_ms {
            return Err(PdfInterchangeError::AccessDenied(
                "PDF backend approval is not currently valid".to_owned(),
            ));
        }
        if self.approval_sha256 != hash_without(self, &["approval_sha256"])? {
            return Err(integrity("PDF backend approval hash differs"));
        }
        let payload = signature_payload(self, &["signature_hex", "approval_sha256"])?;
        verify_signature(key, &payload, &self.signature_hex)
    }

    fn validate_content(&self) -> Result<(), PdfInterchangeError> {
        if self.schema_version != 1
            || self.allowed_source_formats.is_empty()
            || self.allowed_source_formats.len() > 5
            || self.approved_profile_ids.is_empty()
            || self.approved_profile_ids.len() > 3
            || self.issued_at_unix_ms == 0
            || self.expires_at_unix_ms <= self.issued_at_unix_ms
            || self.expires_at_unix_ms - self.issued_at_unix_ms > 86_400_000
        {
            return Err(invalid("PDF backend approval bounds differ"));
        }
        for id in [
            &self.approval_id,
            &self.organization_id,
            &self.environment_id,
            &self.signer_id,
            &self.signing_key_id,
        ] {
            validate_id(id, "backend approval identity")?;
        }
        validate_hash(&self.backend_descriptor_sha256, "backend descriptor hash")?;
        validate_signature_hex(&self.signature_hex)?;
        validate_bounded(self)
    }
}

impl PdfFinalizationSealV1 {
    pub fn sign(mut self, key: &SigningKey) -> Result<Self, PdfInterchangeError> {
        self.signature_hex = "00".repeat(64);
        self.seal_sha256 = ZERO_HASH.to_owned();
        self.validate_content()?;
        let payload = signature_payload(&self, &["signature_hex", "seal_sha256"])?;
        self.signature_hex = hex_encode(&key.sign(&payload).to_bytes());
        self.seal_sha256 = hash_without(&self, &["seal_sha256"])?;
        Ok(self)
    }

    pub fn verify(&self, key: &VerifyingKey, now_unix_ms: u64) -> Result<(), PdfInterchangeError> {
        self.validate_content()?;
        if now_unix_ms < self.issued_at_unix_ms || now_unix_ms >= self.expires_at_unix_ms {
            return Err(PdfInterchangeError::AccessDenied(
                "PDF finalization seal is not currently valid".to_owned(),
            ));
        }
        if self.seal_sha256 != hash_without(self, &["seal_sha256"])? {
            return Err(integrity("PDF finalization seal hash differs"));
        }
        let payload = signature_payload(self, &["signature_hex", "seal_sha256"])?;
        verify_signature(key, &payload, &self.signature_hex)
    }

    fn validate_content(&self) -> Result<(), PdfInterchangeError> {
        if self.schema_version != 1
            || self.issued_at_unix_ms == 0
            || self.expires_at_unix_ms <= self.issued_at_unix_ms
            || self.expires_at_unix_ms - self.issued_at_unix_ms > 86_400_000
        {
            return Err(invalid("PDF finalization seal version or TTL differs"));
        }
        for id in [
            &self.seal_id,
            &self.organization_id,
            &self.case_id,
            &self.signer_id,
            &self.signing_key_id,
        ] {
            validate_id(id, "seal identity")?;
        }
        for hash in [
            &self.final_artifact_pair_sha256,
            &self.source_artifact_sha256,
            &self.pdf_artifact_sha256,
            &self.export_profile_sha256,
            &self.post_export_verification_sha256,
            &self.source_tree_sha256,
            &self.protected_audit_terminal_sha256,
        ] {
            validate_hash(hash, "seal hash")?;
        }
        validate_signature_hex(&self.signature_hex)?;
        validate_bounded(self)
    }
}

impl PdfWorkCertificationV1 {
    pub fn sign(mut self, key: &SigningKey) -> Result<Self, PdfInterchangeError> {
        self.signature_hex = "00".repeat(64);
        self.certification_sha256 = ZERO_HASH.to_owned();
        self.validate_content()?;
        let payload = signature_payload(&self, &["signature_hex", "certification_sha256"])?;
        self.signature_hex = hex_encode(&key.sign(&payload).to_bytes());
        self.certification_sha256 = hash_without(&self, &["certification_sha256"])?;
        Ok(self)
    }

    pub fn verify(&self, key: &VerifyingKey, now_unix_ms: u64) -> Result<(), PdfInterchangeError> {
        self.validate_content()?;
        if now_unix_ms < self.issued_at_unix_ms || now_unix_ms >= self.expires_at_unix_ms {
            return Err(PdfInterchangeError::AccessDenied(
                "OFFICE-500 certification is not currently valid".to_owned(),
            ));
        }
        if self.certification_sha256 != hash_without(self, &["certification_sha256"])? {
            return Err(integrity("OFFICE-500 certification hash differs"));
        }
        let payload = signature_payload(self, &["signature_hex", "certification_sha256"])?;
        verify_signature(key, &payload, &self.signature_hex)
    }

    /// Verifies immutable certification provenance without treating it as a current authority.
    ///
    /// This validates the original bounded TTL, canonical hash, and signature at the signed
    /// issuance instant. Callers must separately bind the certification to its archived
    /// completion report and must not use this result as an activation or execution token.
    pub fn verify_archived(&self, key: &VerifyingKey) -> Result<(), PdfInterchangeError> {
        self.verify(key, self.issued_at_unix_ms)
    }

    fn validate_content(&self) -> Result<(), PdfInterchangeError> {
        if self.schema_version != 1
            || self.issued_at_unix_ms == 0
            || self.expires_at_unix_ms <= self.issued_at_unix_ms
            || self.expires_at_unix_ms - self.issued_at_unix_ms > 86_400_000
        {
            return Err(invalid("OFFICE-500 certification version or TTL differs"));
        }
        for id in [
            &self.certification_id,
            &self.signer_id,
            &self.signing_key_id,
        ] {
            validate_id(id, "certification identity")?;
        }
        for hash in [
            &self.completion_report_sha256,
            &self.predecessor_finished_sha256,
            &self.model_artifact_sha256,
            &self.runtime_artifact_sha256,
            &self.word_executable_sha256,
            &self.excel_executable_sha256,
            &self.powerpoint_executable_sha256,
            &self.pdf_render_worker_sha256,
        ] {
            validate_hash(hash, "certification hash")?;
        }
        validate_ids(&self.evidence_ids, "certification evidence")?;
        validate_signature_hex(&self.signature_hex)?;
        validate_bounded(self)
    }
}

/// Strictly parses one bounded PDF contract and rejects unknown fields via the target type.
pub fn parse_pdf_json_strict<T>(bytes: &[u8]) -> Result<T, PdfInterchangeError>
where
    T: serde::de::DeserializeOwned + Serialize,
{
    if bytes.len() > MAX_PDF_JSON_BYTES {
        return Err(PdfInterchangeError::Resource(
            "PDF JSON input exceeds 8 MiB".to_owned(),
        ));
    }
    let value = serde_json::from_slice(bytes)
        .map_err(|error| PdfInterchangeError::Json(error.to_string()))?;
    validate_bounded(&value)?;
    Ok(value)
}

fn signature_payload<T: Serialize>(
    value: &T,
    excluded: &[&str],
) -> Result<Vec<u8>, PdfInterchangeError> {
    let mut object = serde_json::to_value(value)
        .map_err(|error| PdfInterchangeError::Json(error.to_string()))?
        .as_object()
        .cloned()
        .ok_or_else(|| invalid("signed PDF artifact must be an object"))?;
    for field in excluded {
        object.remove(*field);
    }
    serde_json::to_vec(&object).map_err(|error| PdfInterchangeError::Json(error.to_string()))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn validate_signature_hex(value: &str) -> Result<(), PdfInterchangeError> {
    if value.len() != 128 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid("signature must be a 64-byte hexadecimal value"));
    }
    Ok(())
}

fn verify_signature(
    key: &VerifyingKey,
    payload: &[u8],
    signature_hex: &str,
) -> Result<(), PdfInterchangeError> {
    validate_signature_hex(signature_hex)?;
    let bytes = (0..64)
        .map(|index| u8::from_str_radix(&signature_hex[index * 2..index * 2 + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| invalid(error.to_string()))?;
    let bytes: [u8; 64] = bytes
        .try_into()
        .map_err(|_| invalid("signature length differs"))?;
    key.verify(payload, &Signature::from_bytes(&bytes))
        .map_err(|error| integrity(format!("signature verification failed: {error}")))
}

#[cfg(test)]
mod tests;
