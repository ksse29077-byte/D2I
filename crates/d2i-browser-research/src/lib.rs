//! Network-isolated public-web research and controlled-download contracts.

mod browser_session;
mod contracts;
mod disclosure;
mod discovery;
mod download;
mod evidence;
mod network_contracts;
mod recovery;
mod snapshot;
mod snapshot_server;
mod url_admission;
mod validation;

pub use browser_session::*;
pub use contracts::*;
pub use disclosure::*;
pub use discovery::*;
pub use download::*;
pub use evidence::*;
pub use network_contracts::*;
pub use recovery::*;
pub use snapshot::*;
pub use snapshot_server::*;
pub use url_admission::*;
pub use validation::{
    canonical_sha256, parse_json_strict, sha256_bytes, validate_hash, ResearchError, ZERO_HASH,
};

use validation::{hash_without_field, validate_bounded, validate_id};

macro_rules! impl_sealed_contract {
    ($contract:ty, $field:ident) => {
        impl $contract {
            pub fn seal(mut self) -> Result<Self, ResearchError> {
                self.$field = ZERO_HASH.to_owned();
                validate_bounded(&self)?;
                self.$field = hash_without_field(&self, stringify!($field))?;
                Ok(self)
            }

            pub fn validate_seal(&self) -> Result<(), ResearchError> {
                validate_bounded(self)?;
                validate_hash(&self.$field, stringify!($field))?;
                let expected = hash_without_field(self, stringify!($field))?;
                if expected != self.$field {
                    return Err(ResearchError::Integrity(format!(
                        "{} hash differs",
                        stringify!($contract)
                    )));
                }
                Ok(())
            }
        }
    };
}

impl_sealed_contract!(ResearchBriefV1, brief_sha256);
impl_sealed_contract!(ResearchDisclosurePolicyV1, policy_sha256);
impl_sealed_contract!(ResearchDisclosureDecisionV1, decision_sha256);
impl_sealed_contract!(ResearchNetworkProfileV1, network_profile_sha256);
impl_sealed_contract!(ResearchDiscoveryProviderDescriptorV1, descriptor_sha256);
impl_sealed_contract!(SearchPortalProfileV1, profile_sha256);
impl_sealed_contract!(ResearchQueryV1, query_sha256);
impl_sealed_contract!(ResearchDiscoveryResultV1, result_sha256);
impl_sealed_contract!(ResearchUrlAdmissionRequestV1, request_sha256);
impl_sealed_contract!(ResearchUrlAdmissionDecisionV1, decision_sha256);
impl_sealed_contract!(ResearchFetchRequestV1, request_sha256);
impl_sealed_contract!(ResearchHttpMetadataV1, metadata_sha256);
impl_sealed_contract!(ResearchFetchReceiptV1, receipt_sha256);
impl_sealed_contract!(ResearchNetworkWorkerAuthorizationV1, authorization_sha256);
impl_sealed_contract!(ResearchSegmentV1, segment_sha256);
impl_sealed_contract!(ResearchLinkV1, link_sha256);
impl_sealed_contract!(ResearchPageSnapshotV1, snapshot_sha256);
impl_sealed_contract!(ResearchSourcePolicyV1, policy_sha256);
impl_sealed_contract!(ResearchEvidenceExcerptV1, evidence_sha256);
impl_sealed_contract!(ResearchConflictV1, conflict_sha256);
impl_sealed_contract!(ResearchEvidenceBundleV1, bundle_sha256);
impl_sealed_contract!(ResearchClaimV1, claim_sha256);
impl_sealed_contract!(ResearchSufficiencyReportV1, report_sha256);
impl_sealed_contract!(ResearchModelContextSliceV1, context_sha256);
impl_sealed_contract!(ResearchReportV1, report_sha256);
impl_sealed_contract!(BrowserResearchSessionV1, session_sha256);
impl_sealed_contract!(BrowserSnapshotManifestV1, manifest_sha256);
impl_sealed_contract!(ResearchLinkSelectionV1, selection_sha256);
impl_sealed_contract!(ControlledDownloadIntentV1, intent_sha256);
impl_sealed_contract!(ControlledDownloadRequestV1, request_sha256);
impl_sealed_contract!(ControlledDownloadReceiptV1, receipt_sha256);
impl_sealed_contract!(DownloadQuarantineRecordV1, record_sha256);
impl_sealed_contract!(AttachmentTrustReportV1, report_sha256);
impl_sealed_contract!(DownloadValidationReportV1, report_sha256);
impl_sealed_contract!(DownloadPromotionReceiptV1, receipt_sha256);
impl_sealed_contract!(ResearchExperienceRecordV1, experience_sha256);
impl_sealed_contract!(ResearchWorkReplayReportV1, report_sha256);
impl_sealed_contract!(ResearchWorkCompletionReportV1, finished_sha256);
impl_sealed_contract!(ResearchWorkCertificationV1, certification_sha256);
impl_sealed_contract!(AttachmentPolicySnapshotV1, snapshot_sha256);
impl_sealed_contract!(AttachmentPolicyProbeV1, probe_sha256);
impl_sealed_contract!(AttachmentPolicyQualificationV1, qualification_sha256);
impl_sealed_contract!(ResearchWorkCloseoutCertificationV1, certification_sha256);

pub const REQUIRED_REPLAY_SCENARIOS: u32 = 128;
pub const REQUIRED_REPLAY_RUNS: u32 = 100;

impl ResearchExperienceRecordV1 {
    pub fn validate_gate(&self) -> Result<(), ResearchError> {
        self.validate_seal()?;
        for value in [&self.experience_id, &self.organization_id, &self.case_id] {
            validate_id(value, "research experience identity")?;
        }
        for (value, field) in [
            (&self.brief_sha256, "experience brief hash"),
            (&self.evidence_bundle_sha256, "experience evidence hash"),
            (
                &self.sufficiency_report_sha256,
                "experience sufficiency hash",
            ),
            (&self.report_sha256, "experience report hash"),
        ] {
            validate_hash(value, field)?;
        }
        let negative = matches!(
            self.case_kind,
            ResearchExperienceCaseKindV1::SsrfRejection
                | ResearchExperienceCaseKindV1::UrlAttackRejection
                | ResearchExperienceCaseKindV1::RedirectAttackRejection
                | ResearchExperienceCaseKindV1::HttpBoundRejection
                | ResearchExperienceCaseKindV1::PromptInjectionRejection
                | ResearchExperienceCaseKindV1::QueryLeakageRejection
                | ResearchExperienceCaseKindV1::MaliciousDownloadRejection
                | ResearchExperienceCaseKindV1::FilenameAttackRejection
                | ResearchExperienceCaseKindV1::MimeMagicRejection
                | ResearchExperienceCaseKindV1::BrowserModelEgressRejection
        );
        let expected_outcome = if negative {
            ResearchExperienceOutcomeV1::NegativeRejected
        } else {
            ResearchExperienceOutcomeV1::RoutineComplete
        };
        let expected_model_used = matches!(
            self.case_kind,
            ResearchExperienceCaseKindV1::ModelAssistedSynthesis
        );
        if self.schema_version != 1
            || self.operation_count == 0
            || self.outcome != expected_outcome
            || self.model_used != expected_model_used
        {
            return Err(ResearchError::Integrity(
                "research experience outcome or model-use evidence differs from its closed case"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

impl ResearchWorkReplayReportV1 {
    pub fn validate_gate(&self) -> Result<(), ResearchError> {
        self.validate_seal()?;
        let required =
            u64::from(REQUIRED_REPLAY_SCENARIOS).saturating_mul(u64::from(REQUIRED_REPLAY_RUNS));
        if self.schema_version != 1
            || self.scenario_count != REQUIRED_REPLAY_SCENARIOS
            || self.repetitions_per_scenario != REQUIRED_REPLAY_RUNS
            || self.logical_replay_count != required
            || self.external_network_request_count != 0
            || self.deterministic_match_count != required
            || self.blind_replay_count != 0
        {
            return Err(ResearchError::Integrity(
                "OFFICE-600 logical replay gate differs".to_owned(),
            ));
        }
        Ok(())
    }
}

impl ResearchNetworkWorkerAuthorizationV1 {
    pub fn sign(mut self, key: &ed25519_dalek::SigningKey) -> Result<Self, ResearchError> {
        use ed25519_dalek::Signer;

        self.signature_hex = "00".repeat(64);
        self.authorization_sha256 = ZERO_HASH.to_owned();
        self.validate_content()?;
        self.signature_hex = hex_encode(
            &key.sign(&signature_payload(
                &self,
                &["signature_hex", "authorization_sha256"],
            )?)
            .to_bytes(),
        );
        self.seal()
    }

    pub fn verify(
        &self,
        key: &ed25519_dalek::VerifyingKey,
        now_unix_ms: u64,
        expected_worker_sha256: &str,
    ) -> Result<(), ResearchError> {
        use ed25519_dalek::{Signature, Verifier};

        self.validate_content()?;
        self.validate_seal()?;
        validate_hash(expected_worker_sha256, "expected network worker hash")?;
        if self.worker_executable_sha256 != expected_worker_sha256
            || now_unix_ms < self.issued_at_unix_ms
            || now_unix_ms >= self.expires_at_unix_ms
        {
            return Err(ResearchError::AccessDenied(
                "network worker authorization is expired or bound to another executable".to_owned(),
            ));
        }
        let signature = Signature::from_bytes(&hex_decode_signature(&self.signature_hex)?);
        key.verify(
            &signature_payload(self, &["signature_hex", "authorization_sha256"])?,
            &signature,
        )
        .map_err(|_| ResearchError::Integrity("network authorization signature differs".to_owned()))
    }

    fn validate_content(&self) -> Result<(), ResearchError> {
        for value in [
            &self.authorization_id,
            &self.organization_id,
            &self.case_id,
            &self.nonce_id,
            &self.signer_id,
            &self.signing_key_id,
        ] {
            validate_id(value, "network worker authorization identity")?;
        }
        if self.schema_version != 1
            || self.maximum_response_bytes == 0
            || self.maximum_response_bytes > MAX_INDIVIDUAL_DOWNLOAD_BYTES
            || self.issued_at_unix_ms == 0
            || self.expires_at_unix_ms <= self.issued_at_unix_ms
            || self.expires_at_unix_ms - self.issued_at_unix_ms > 300_000
        {
            return Err(ResearchError::Invalid(
                "network worker authorization bounds differ".to_owned(),
            ));
        }
        validate_hash(&self.request_sha256, "network worker request hash")?;
        validate_hash(
            &self.worker_executable_sha256,
            "network worker executable hash",
        )?;
        if self.signature_hex.len() != 128
            || !self
                .signature_hex
                .bytes()
                .all(|value| value.is_ascii_hexdigit() && !value.is_ascii_uppercase())
        {
            return Err(ResearchError::Invalid(
                "network worker signature must be 64-byte lowercase hex".to_owned(),
            ));
        }
        Ok(())
    }
}

impl ResearchWorkCompletionReportV1 {
    pub fn validate_gate(&self) -> Result<(), ResearchError> {
        self.validate_seal()?;
        for hash in [
            &self.source_tree_sha256,
            &self.predecessor_finished_sha256,
            &self.replay_report_sha256,
            &self.protected_audit_terminal_sha256,
        ] {
            validate_hash(hash, "completion hash")?;
        }
        let complete = self.schema_version == 1
            && self.research_case_count >= 24
            && self.routine_case_count >= 14
            && self.security_negative_case_count >= 10
            && self.external_request_count >= 2
            && self.external_origin_count >= 2
            && self.external_bytes_received > 0
            && self.ssrf_rejection_count >= 10
            && self.snapshot_page_count >= 5
            && self.evidence_excerpt_count >= 1
            && self.actual_qwen_invocation_count >= 2
            && self.model_free_case_count >= 1
            && self.actual_download_count >= 1
            && self.promoted_artifact_count >= 1
            && self.rejected_download_count >= 5
            && self.crash_window_count == 14
            && self.protected_audit_record_count >= 16
            && self.security == ResearchSecurityMetricsV1::default()
            && self.residual == ResearchResidualMetricsV1::default()
            && self.browser_loopback_only_evidence
            && self.network_worker_sole_egress_evidence
            && self.safe_snapshot_evidence
            && self.evidence_grounding_evidence
            && self.controlled_download_evidence
            && self.attachment_trust_evidence
            && self.format_validation_evidence
            && self.workspace_promotion_evidence
            && self.model_free_research_evidence
            && self.routine_human_touch_zero
            && self.complete;
        if !complete {
            return Err(ResearchError::Integrity(
                "OFFICE-600 Completion gates are incomplete".to_owned(),
            ));
        }
        Ok(())
    }
}

impl ResearchWorkCertificationV1 {
    pub fn sign(mut self, key: &ed25519_dalek::SigningKey) -> Result<Self, ResearchError> {
        use ed25519_dalek::Signer;

        self.signature_hex = "00".repeat(64);
        self.certification_sha256 = ZERO_HASH.to_owned();
        self.validate_content()?;
        let payload = signature_payload(&self, &["signature_hex", "certification_sha256"])?;
        self.signature_hex = hex_encode(&key.sign(&payload).to_bytes());
        self.seal()
    }

    pub fn verify(
        &self,
        key: &ed25519_dalek::VerifyingKey,
        now_unix_ms: u64,
    ) -> Result<(), ResearchError> {
        use ed25519_dalek::{Signature, Verifier};

        self.validate_content()?;
        self.validate_seal()?;
        if now_unix_ms < self.issued_at_unix_ms || now_unix_ms >= self.expires_at_unix_ms {
            return Err(ResearchError::AccessDenied(
                "OFFICE-600 certification is not currently valid".to_owned(),
            ));
        }
        let bytes = hex_decode_signature(&self.signature_hex)?;
        let signature = Signature::from_bytes(&bytes);
        key.verify(
            &signature_payload(self, &["signature_hex", "certification_sha256"])?,
            &signature,
        )
        .map_err(|_| ResearchError::Integrity("certification signature differs".to_owned()))
    }

    fn validate_content(&self) -> Result<(), ResearchError> {
        for value in [
            &self.certification_id,
            &self.signer_id,
            &self.signing_key_id,
        ] {
            validate_id(value, "OFFICE-600 certification identity")?;
        }
        for evidence_id in &self.evidence_ids {
            validate_id(evidence_id, "OFFICE-600 certification evidence")?;
        }
        if self.schema_version != 1
            || self.issued_at_unix_ms == 0
            || self.expires_at_unix_ms <= self.issued_at_unix_ms
            || self.expires_at_unix_ms - self.issued_at_unix_ms > 86_400_000
            || self.evidence_ids.is_empty()
        {
            return Err(ResearchError::Invalid(
                "OFFICE-600 certification bounds differ".to_owned(),
            ));
        }
        for hash in [
            &self.completion_report_sha256,
            &self.predecessor_finished_sha256,
            &self.network_worker_sha256,
            &self.edge_executable_sha256,
            &self.edge_driver_executable_sha256,
            &self.model_artifact_sha256,
            &self.runtime_artifact_sha256,
        ] {
            validate_hash(hash, "certification hash")?;
        }
        if self.signature_hex.len() != 128
            || !self
                .signature_hex
                .bytes()
                .all(|value| value.is_ascii_hexdigit() && !value.is_ascii_uppercase())
        {
            return Err(ResearchError::Invalid(
                "certification signature must be 64-byte lowercase hex".to_owned(),
            ));
        }
        Ok(())
    }
}

impl AttachmentPolicySnapshotV1 {
    pub fn validate_gate(&self) -> Result<(), ResearchError> {
        self.validate_seal()?;
        validate_attachment_policy_identity(&self.user_sid, &self.admx_sha256)?;
        for hash in [
            &self.low_risk_value_sha256,
            &self.moderate_risk_value_sha256,
            &self.high_risk_value_sha256,
            &self.policy_state_sha256,
        ] {
            validate_hash(hash, "attachment policy snapshot hash")?;
        }
        if let Some(hash) = &self.attachments_policy_sha256 {
            validate_hash(hash, "attachments policy hash")?;
        }
        for (exists, value_type, bytes, expected_hash) in [
            (
                self.low_risk_value_exists,
                self.low_risk_value_type.as_str(),
                self.low_risk_value_bytes_base64.as_str(),
                self.low_risk_value_sha256.as_str(),
            ),
            (
                self.moderate_risk_value_exists,
                self.moderate_risk_value_type.as_str(),
                self.moderate_risk_value_bytes_base64.as_str(),
                self.moderate_risk_value_sha256.as_str(),
            ),
            (
                self.high_risk_value_exists,
                self.high_risk_value_type.as_str(),
                self.high_risk_value_bytes_base64.as_str(),
                self.high_risk_value_sha256.as_str(),
            ),
        ] {
            if !matches!(
                value_type,
                "none"
                    | "reg_sz"
                    | "reg_expand_sz"
                    | "reg_binary"
                    | "reg_dword"
                    | "reg_multi_sz"
                    | "reg_qword"
                    | "reg_none"
            ) || exists == (value_type == "none")
                || !exists && !bytes.is_empty()
            {
                return Err(ResearchError::Integrity(
                    "attachment policy value snapshot differs".to_owned(),
                ));
            }
            let decoded = decode_base64_bounded(bytes, 65_536)?;
            if sha256_bytes(&decoded) != expected_hash {
                return Err(ResearchError::Integrity(
                    "attachment policy raw value hash differs".to_owned(),
                ));
            }
        }
        if self.schema_version != 1 || self.captured_at_unix_ms == 0 {
            return Err(ResearchError::Invalid(
                "attachment policy snapshot bounds differ".to_owned(),
            ));
        }
        Ok(())
    }
}

impl AttachmentPolicyProbeV1 {
    pub fn validate_gate(&self) -> Result<(), ResearchError> {
        self.validate_seal()?;
        validate_attachment_policy_identity(&self.user_sid, &self.admx_sha256)?;
        for hash in [&self.original_policy_sha256, &self.staged_policy_sha256] {
            validate_hash(hash, "attachment policy probe hash")?;
        }
        validate_attachment_policy_decisions(
            self.elevated,
            &self.completion_low_risk_extensions,
            self.txt_checkpolicy,
            self.csv_checkpolicy,
            self.pdf_checkpolicy,
            self.higher_precedence_txt_conflict,
        )?;
        if self.schema_version != 1 || self.original_policy_sha256 == self.staged_policy_sha256 {
            return Err(ResearchError::Integrity(
                "attachment policy probe state differs".to_owned(),
            ));
        }
        Ok(())
    }
}

impl AttachmentPolicyQualificationV1 {
    pub fn validate_gate(&self) -> Result<(), ResearchError> {
        self.validate_seal()?;
        validate_attachment_policy_identity(&self.user_sid, &self.admx_sha256)?;
        for hash in [
            &self.original_policy_sha256,
            &self.staged_policy_sha256,
            &self.restored_policy_sha256,
        ] {
            validate_hash(hash, "attachment policy qualification hash")?;
        }
        validate_attachment_policy_decisions(
            self.elevated,
            &self.completion_low_risk_extensions,
            self.txt_checkpolicy,
            self.csv_checkpolicy,
            self.pdf_checkpolicy,
            self.higher_precedence_txt_conflict,
        )?;
        if self.schema_version != 1
            || self.qualification_status != AttachmentPolicyQualificationStatusV1::Qualified
            || !self.restored_exactly
            || self.original_policy_sha256 != self.restored_policy_sha256
            || self.original_policy_sha256 == self.staged_policy_sha256
            || self.qualification_total_microseconds
                < self
                    .policy_stage_microseconds
                    .saturating_add(self.policy_restore_microseconds)
            || [
                self.attachment_prompt_bypass_count,
                self.attachment_policy_scope_broadening_count,
                self.zone_information_bypass_count,
                self.security_ui_auto_approval_count,
                self.csv_automatic_promotion_count,
                self.pdf_automatic_promotion_count,
                self.temporary_attachment_policy_count,
            ]
            .iter()
            .any(|count| *count != 0)
        {
            return Err(ResearchError::Integrity(
                "attachment policy qualification gates differ".to_owned(),
            ));
        }
        Ok(())
    }
}

impl ResearchWorkCloseoutCertificationV1 {
    pub fn sign(mut self, key: &ed25519_dalek::SigningKey) -> Result<Self, ResearchError> {
        use ed25519_dalek::Signer;

        self.signature_hex = "00".repeat(64);
        self.certification_sha256 = ZERO_HASH.to_owned();
        self.validate_content()?;
        let payload = signature_payload(&self, &["signature_hex", "certification_sha256"])?;
        self.signature_hex = hex_encode(&key.sign(&payload).to_bytes());
        self.seal()
    }

    pub fn verify(
        &self,
        key: &ed25519_dalek::VerifyingKey,
        now_unix_ms: u64,
    ) -> Result<(), ResearchError> {
        use ed25519_dalek::{Signature, Verifier};

        self.validate_content()?;
        self.validate_seal()?;
        if now_unix_ms < self.issued_at_unix_ms || now_unix_ms >= self.expires_at_unix_ms {
            return Err(ResearchError::AccessDenied(
                "OFFICE-600 closeout certification is not currently valid".to_owned(),
            ));
        }
        let signature = Signature::from_bytes(&hex_decode_signature(&self.signature_hex)?);
        key.verify(
            &signature_payload(self, &["signature_hex", "certification_sha256"])?,
            &signature,
        )
        .map_err(|_| {
            ResearchError::Integrity("closeout certification signature differs".to_owned())
        })
    }

    fn validate_content(&self) -> Result<(), ResearchError> {
        for value in [
            &self.certification_id,
            &self.signer_id,
            &self.signing_key_id,
        ] {
            validate_id(value, "OFFICE-600 closeout certification identity")?;
        }
        validate_attachment_policy_identity(&self.user_sid, &self.admx_sha256)?;
        for hash in [
            &self.completion_report_sha256,
            &self.execution_certification_sha256,
            &self.attachment_policy_qualification_sha256,
            &self.original_policy_sha256,
            &self.staged_policy_sha256,
            &self.restored_policy_sha256,
            &self.source_tree_sha256,
        ] {
            validate_hash(hash, "OFFICE-600 closeout certification hash")?;
        }
        if self.schema_version != 1
            || self.issued_at_unix_ms == 0
            || self.expires_at_unix_ms <= self.issued_at_unix_ms
            || self.expires_at_unix_ms - self.issued_at_unix_ms > 86_400_000
            || self.original_policy_sha256 != self.restored_policy_sha256
            || self.original_policy_sha256 == self.staged_policy_sha256
            || self.signature_hex.len() != 128
            || !self
                .signature_hex
                .bytes()
                .all(|value| value.is_ascii_hexdigit() && !value.is_ascii_uppercase())
        {
            return Err(ResearchError::Invalid(
                "OFFICE-600 closeout certification bounds differ".to_owned(),
            ));
        }
        Ok(())
    }
}

fn validate_attachment_policy_identity(
    user_sid: &str,
    admx_sha256: &str,
) -> Result<(), ResearchError> {
    if !user_sid.starts_with("S-1-") || user_sid.len() > 184 {
        return Err(ResearchError::Invalid(
            "attachment policy user SID differs".to_owned(),
        ));
    }
    validate_hash(admx_sha256, "AttachmentManager ADMX hash")
}

fn validate_attachment_policy_decisions(
    elevated: bool,
    extensions: &[String],
    txt: AttachmentPolicyDecisionV1,
    csv: AttachmentPolicyDecisionV1,
    pdf: AttachmentPolicyDecisionV1,
    higher_precedence_conflict: bool,
) -> Result<(), ResearchError> {
    if !elevated
        || extensions != [".txt"]
        || txt != AttachmentPolicyDecisionV1::Enable
        || csv != AttachmentPolicyDecisionV1::Prompt
        || pdf != AttachmentPolicyDecisionV1::Prompt
        || higher_precedence_conflict
    {
        return Err(ResearchError::AccessDenied(
            "Attachment Services qualification scope differs".to_owned(),
        ));
    }
    Ok(())
}

fn decode_base64_bounded(value: &str, maximum_bytes: usize) -> Result<Vec<u8>, ResearchError> {
    if value.len() % 4 != 0 || value.len() > maximum_bytes.saturating_add(2) / 3 * 4 {
        return Err(ResearchError::Resource(
            "attachment policy raw value exceeds its bound".to_owned(),
        ));
    }
    let mut output = Vec::with_capacity(value.len() / 4 * 3);
    for (chunk_index, chunk) in value.as_bytes().chunks_exact(4).enumerate() {
        let final_chunk = chunk_index + 1 == value.len() / 4;
        let padding = if chunk[3] == b'=' {
            if chunk[2] == b'=' {
                2
            } else {
                1
            }
        } else {
            0
        };
        if (!final_chunk && padding != 0)
            || chunk[..4 - padding].contains(&b'=')
            || chunk[4 - padding..].iter().any(|byte| *byte != b'=')
        {
            return Err(ResearchError::Invalid(
                "attachment policy raw value is not canonical base64".to_owned(),
            ));
        }
        let mut values = [0_u8; 4];
        for (index, byte) in chunk[..4 - padding].iter().enumerate() {
            values[index] = decode_base64_symbol(*byte)?;
        }
        if padding == 2 && values[1] & 0x0f != 0 || padding == 1 && values[2] & 0x03 != 0 {
            return Err(ResearchError::Invalid(
                "attachment policy raw value has noncanonical padding".to_owned(),
            ));
        }
        output.push(values[0] << 2 | values[1] >> 4);
        if padding < 2 {
            output.push(values[1] << 4 | values[2] >> 2);
        }
        if padding == 0 {
            output.push(values[2] << 6 | values[3]);
        }
    }
    if output.len() > maximum_bytes {
        return Err(ResearchError::Resource(
            "attachment policy raw value exceeds its decoded bound".to_owned(),
        ));
    }
    Ok(output)
}

fn decode_base64_symbol(value: u8) -> Result<u8, ResearchError> {
    match value {
        b'A'..=b'Z' => Ok(value - b'A'),
        b'a'..=b'z' => Ok(value - b'a' + 26),
        b'0'..=b'9' => Ok(value - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(ResearchError::Invalid(
            "attachment policy raw value is not base64".to_owned(),
        )),
    }
}

fn signature_payload<T: serde::Serialize>(
    value: &T,
    excluded_fields: &[&str],
) -> Result<Vec<u8>, ResearchError> {
    let mut object = serde_json::to_value(value)
        .map_err(|error| ResearchError::Json(error.to_string()))?
        .as_object()
        .cloned()
        .ok_or_else(|| ResearchError::Invalid("certification must be an object".to_owned()))?;
    for field in excluded_fields {
        object.remove(*field);
    }
    serde_json::to_vec(&object).map_err(|error| ResearchError::Json(error.to_string()))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode_signature(value: &str) -> Result<[u8; 64], ResearchError> {
    if value.len() != 128 {
        return Err(ResearchError::Invalid(
            "certification signature length differs".to_owned(),
        ));
    }
    let mut result = [0_u8; 64];
    for (index, byte) in result.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&value[offset..offset + 2], 16).map_err(|_| {
            ResearchError::Invalid("certification signature is not hexadecimal".to_owned())
        })?;
    }
    Ok(result)
}

#[cfg(test)]
mod tests;
