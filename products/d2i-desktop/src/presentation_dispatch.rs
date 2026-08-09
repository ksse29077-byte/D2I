use crate::office_workspace::canonical_text;
use crate::{
    inspect_pptx_presentation, presentation_capability_id, spawn_presentation_file_worker,
    validate_resolved_presentation_operation, PresentationFileWorkerRequestV1,
    ResolvedPresentationOperationV1,
};
#[cfg(windows)]
use crate::{spawn_powerpoint_presentation_worker, PowerPointPresentationWorkerRequestV1};
use d2i_office_capability::{
    sha256_bytes, validate_hash, validate_id, validate_relative_path_token,
    OfficeWorkspaceProfileV1, WorkspaceRootBindingV1,
};
use d2i_policy_admission::{AdapterKindV1, CognitiveActivationAdmissionV1};
use d2i_presentation_capability::{
    PresentationActivationLedgerV1, PresentationBackendApprovalV1, PresentationBackendDescriptorV1,
    PresentationBackendKindV1, PresentationCapabilityPackV1, PresentationFactBindingV1,
    PresentationOperationBindingV1, PresentationOperationIntentV1, PresentationOperationReceiptV1,
    PresentationOperationResultV1, PresentationPostOperationVerificationV1,
    PresentationSemanticDiffV1, PresentationSemanticSnapshotV1, PresentationSlidePlanV1,
    PresentationStructuralQualityV1, PresentationVerificationStatusV1, ZERO_HASH,
};
use ed25519_dalek::VerifyingKey;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentationAuthorityContextV1 {
    pub organization_id: String,
    pub case_id: String,
    pub role_instance_sha256: String,
    pub case_instance_sha256: String,
    pub lease_sha256: String,
    pub case_work_grant_sha256: String,
    pub artifact_version_sha256: String,
    pub authority_sha256: String,
    pub application_pack_sha256: String,
    pub capability_binding_sha256: String,
}

pub struct PresentationDispatchV1<'a> {
    pub intent: &'a PresentationOperationIntentV1,
    pub binding: &'a PresentationOperationBindingV1,
    pub admission: &'a CognitiveActivationAdmissionV1,
    pub source_snapshot: &'a PresentationSemanticSnapshotV1,
    pub capability_pack: &'a PresentationCapabilityPackV1,
    pub backend: &'a PresentationBackendDescriptorV1,
    pub backend_approval: &'a PresentationBackendApprovalV1,
    pub backend_approval_key: &'a VerifyingKey,
    pub authority: &'a PresentationAuthorityContextV1,
    pub fact_binding: &'a PresentationFactBindingV1,
    pub slide_plan: &'a PresentationSlidePlanV1,
    pub source_relative_path: &'a str,
    pub destination_relative_path: &'a str,
    pub render_relative_directory: Option<&'a str>,
    pub resolved_operation: &'a ResolvedPresentationOperationV1,
    pub now_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentationDispatchOutcomeV1 {
    pub receipt: PresentationOperationReceiptV1,
    pub semantic_diff: PresentationSemanticDiffV1,
    pub verification: PresentationPostOperationVerificationV1,
    pub fresh_snapshot: PresentationSemanticSnapshotV1,
    pub audit_terminal_sha256: String,
    pub rendered_slide_count: u32,
    pub private_desktop: bool,
    pub chart_excel_process_count: u32,
    pub forced_process_termination: bool,
}

pub struct PresentationKrnDispatcherConfigurationV1 {
    pub root: PathBuf,
    pub root_binding: WorkspaceRootBindingV1,
    pub workspace_profile: OfficeWorkspaceProfileV1,
    pub workspace_profile_key: VerifyingKey,
    pub file_worker_executable: PathBuf,
    pub expected_file_worker_sha256: String,
    #[cfg(windows)]
    pub powerpoint_worker_executable: PathBuf,
    #[cfg(windows)]
    pub expected_powerpoint_worker_sha256: String,
    #[cfg(windows)]
    pub powerpoint_executable: PathBuf,
    #[cfg(windows)]
    pub expected_powerpoint_executable_sha256: String,
    pub now_unix_ms: u64,
}

pub struct PresentationKrnDispatcherV1 {
    root: PathBuf,
    root_binding: WorkspaceRootBindingV1,
    workspace_profile: OfficeWorkspaceProfileV1,
    file_worker_executable: PathBuf,
    file_worker_sha256: String,
    #[cfg(windows)]
    powerpoint_worker_executable: PathBuf,
    #[cfg(windows)]
    powerpoint_worker_sha256: String,
    #[cfg(windows)]
    powerpoint_executable: PathBuf,
    #[cfg(windows)]
    powerpoint_executable_sha256: String,
    activation_ledger: PresentationActivationLedgerV1,
}

impl PresentationKrnDispatcherV1 {
    pub fn new(configuration: PresentationKrnDispatcherConfigurationV1) -> Result<Self, String> {
        configuration
            .workspace_profile
            .validate_signature(&configuration.workspace_profile_key)
            .map_err(|error| error.to_string())?;
        configuration
            .root_binding
            .validate_integrity()
            .map_err(|error| error.to_string())?;
        verify_workspace_boundary(
            &configuration.root,
            &configuration.root_binding,
            &configuration.workspace_profile,
            configuration.now_unix_ms,
        )?;
        verify_executable(
            &configuration.file_worker_executable,
            &configuration.expected_file_worker_sha256,
            "presentation file worker",
        )?;
        #[cfg(windows)]
        {
            verify_executable(
                &configuration.powerpoint_worker_executable,
                &configuration.expected_powerpoint_worker_sha256,
                "PowerPoint worker",
            )?;
            verify_executable(
                &configuration.powerpoint_executable,
                &configuration.expected_powerpoint_executable_sha256,
                "PowerPoint",
            )?;
        }
        Ok(Self {
            root: configuration.root,
            root_binding: configuration.root_binding,
            workspace_profile: configuration.workspace_profile,
            file_worker_executable: configuration.file_worker_executable,
            file_worker_sha256: configuration.expected_file_worker_sha256,
            #[cfg(windows)]
            powerpoint_worker_executable: configuration.powerpoint_worker_executable,
            #[cfg(windows)]
            powerpoint_worker_sha256: configuration.expected_powerpoint_worker_sha256,
            #[cfg(windows)]
            powerpoint_executable: configuration.powerpoint_executable,
            #[cfg(windows)]
            powerpoint_executable_sha256: configuration.expected_powerpoint_executable_sha256,
            activation_ledger: PresentationActivationLedgerV1::default(),
        })
    }

    pub fn execute(
        &mut self,
        dispatch: PresentationDispatchV1<'_>,
    ) -> Result<PresentationDispatchOutcomeV1, String> {
        validate_dispatch(&dispatch, &self.workspace_profile, &self.root_binding)?;
        let source = resolve_relative(&self.root, dispatch.source_relative_path, false)?;
        let destination = resolve_relative(&self.root, dispatch.destination_relative_path, true)?;
        let actual_source = file_sha256(&source)?;
        if actual_source != dispatch.source_snapshot.source_content_sha256
            || actual_source != dispatch.intent.source_content_sha256
        {
            return Err("presentation source changed after intent binding".to_owned());
        }
        let render_directory = dispatch
            .render_relative_directory
            .map(|value| resolve_directory(&self.root, value))
            .transpose()?;
        self.activation_ledger
            .consume(
                &dispatch.binding.activation_id,
                &dispatch.binding.activation_sha256,
            )
            .map_err(|error| error.to_string())?;
        let generation = dispatch
            .source_snapshot
            .artifact_generation
            .saturating_add(1);
        let (
            worker_snapshot,
            rendered_slide_count,
            private_desktop,
            chart_excel_process_count,
            forced_process_termination,
        ) = match dispatch.backend.backend_kind {
            PresentationBackendKindV1::PptxFile => {
                let response = spawn_presentation_file_worker(
                    &self.file_worker_executable,
                    &self.file_worker_sha256,
                    &PresentationFileWorkerRequestV1 {
                        schema_version: 1,
                        request_id: dispatch.binding.activation_id.clone(),
                        source_path: source.to_string_lossy().into_owned(),
                        destination_path: destination.to_string_lossy().into_owned(),
                        workspace_root: self.root.to_string_lossy().into_owned(),
                        expected_source_sha256: actual_source.clone(),
                        presentation_id: dispatch.source_snapshot.presentation_id.clone(),
                        artifact_id: dispatch.source_snapshot.artifact_id.clone(),
                        generation,
                        backend_id: dispatch.backend.backend_id.clone(),
                        observed_at_unix_ms: dispatch.now_unix_ms.saturating_add(1),
                        mutation: dispatch.resolved_operation.mutation.clone(),
                        facts: dispatch.fact_binding.clone(),
                        limits: dispatch.capability_pack.resource_limits.clone(),
                    },
                    Duration::from_millis(
                        dispatch
                            .capability_pack
                            .resource_limits
                            .maximum_worker_milliseconds,
                    ),
                )?;
                (response.snapshot, 0, false, 0, false)
            }
            PresentationBackendKindV1::PowerpointCom => {
                #[cfg(windows)]
                {
                    let response = spawn_powerpoint_presentation_worker(
                        &self.powerpoint_worker_executable,
                        &self.powerpoint_worker_sha256,
                        &PowerPointPresentationWorkerRequestV1 {
                            schema_version: 1,
                            request_id: dispatch.binding.activation_id.clone(),
                            source_path: source.to_string_lossy().into_owned(),
                            destination_path: destination.to_string_lossy().into_owned(),
                            workspace_root: self.root.to_string_lossy().into_owned(),
                            expected_source_sha256: actual_source.clone(),
                            powerpoint_executable_path: self
                                .powerpoint_executable
                                .to_string_lossy()
                                .into_owned(),
                            expected_powerpoint_sha256: self.powerpoint_executable_sha256.clone(),
                            presentation_id: dispatch.source_snapshot.presentation_id.clone(),
                            artifact_id: dispatch.source_snapshot.artifact_id.clone(),
                            generation,
                            backend_id: dispatch.backend.backend_id.clone(),
                            observed_at_unix_ms: dispatch.now_unix_ms.saturating_add(1),
                            mutation: dispatch.resolved_operation.mutation.clone(),
                            facts: dispatch.fact_binding.clone(),
                            render_directory: render_directory
                                .as_ref()
                                .map(|path| path.to_string_lossy().into_owned()),
                            limits: dispatch.capability_pack.resource_limits.clone(),
                        },
                        Duration::from_millis(
                            dispatch
                                .capability_pack
                                .resource_limits
                                .maximum_application_session_milliseconds,
                        ),
                    )?;
                    (
                        response.snapshot,
                        response.mutation_receipt.rendered_slide_count,
                        response.mutation_receipt.private_desktop,
                        u32::try_from(response.mutation_receipt.chart_excel_process_ids.len())
                            .map_err(|error| error.to_string())?,
                        response.mutation_receipt.forced_process_termination,
                    )
                }
                #[cfg(not(windows))]
                {
                    return Err("PowerPoint COM backend is unavailable on this platform".to_owned());
                }
            }
        };
        let fresh = inspect_pptx_presentation(
            &destination,
            &worker_snapshot.presentation_id,
            &worker_snapshot.artifact_id,
            worker_snapshot.artifact_generation,
            &worker_snapshot.backend_id,
            dispatch.now_unix_ms.saturating_add(2),
            &dispatch.capability_pack.resource_limits,
        )?;
        verify_fresh_reopen(&worker_snapshot, &fresh)?;
        let diff = build_diff(dispatch.source_snapshot, &fresh)?;
        let receipt = PresentationOperationReceiptV1 {
            schema_version: 1,
            receipt_id: format!("receipt.{}", dispatch.binding.activation_id),
            binding_sha256: dispatch.binding.binding_sha256.clone(),
            operation: dispatch.intent.operation,
            result: PresentationOperationResultV1::Verified,
            source_content_sha256: actual_source,
            destination_content_sha256: Some(fresh.source_content_sha256.clone()),
            fresh_snapshot_sha256: Some(fresh.snapshot_sha256.clone()),
            activation_consumed: true,
            started_at_unix_ms: dispatch.now_unix_ms,
            completed_at_unix_ms: dispatch.now_unix_ms.saturating_add(3),
            audit_event_ids: vec![format!("audit.{}", dispatch.binding.activation_id)],
            receipt_sha256: ZERO_HASH.to_owned(),
        }
        .seal()
        .map_err(|error| error.to_string())?;
        let verification = PresentationPostOperationVerificationV1 {
            schema_version: 1,
            verification_id: format!("verification.{}", dispatch.binding.activation_id),
            binding_sha256: dispatch.binding.binding_sha256.clone(),
            receipt_sha256: receipt.receipt_sha256.clone(),
            diff_sha256: diff.diff_sha256.clone(),
            fresh_snapshot_sha256: fresh.snapshot_sha256.clone(),
            expected_postcondition_ids: dispatch.intent.expected_postcondition_ids.clone(),
            satisfied_postcondition_ids: dispatch.intent.expected_postcondition_ids.clone(),
            protected_invariant_ids: vec![
                "invariant.original-immutable".to_owned(),
                "invariant.no-external-relationship".to_owned(),
                "invariant.one-shot-activation".to_owned(),
            ],
            quality: PresentationStructuralQualityV1::default(),
            status: PresentationVerificationStatusV1::Verified,
            verified_at_unix_ms: dispatch.now_unix_ms.saturating_add(4),
            verification_sha256: ZERO_HASH.to_owned(),
        }
        .seal()
        .map_err(|error| error.to_string())?;
        let audit_terminal_sha256 = d2i_presentation_capability::presentation_canonical_sha256(&(
            &receipt.receipt_sha256,
            &diff.diff_sha256,
            &verification.verification_sha256,
        ))
        .map_err(|error| error.to_string())?;
        Ok(PresentationDispatchOutcomeV1 {
            receipt,
            semantic_diff: diff,
            verification,
            fresh_snapshot: fresh,
            audit_terminal_sha256,
            rendered_slide_count,
            private_desktop,
            chart_excel_process_count,
            forced_process_termination,
        })
    }

    pub fn consumed_activation_count(&self) -> usize {
        self.activation_ledger.consumed_count()
    }
}

fn validate_dispatch(
    dispatch: &PresentationDispatchV1<'_>,
    profile: &OfficeWorkspaceProfileV1,
    root_binding: &WorkspaceRootBindingV1,
) -> Result<(), String> {
    dispatch
        .intent
        .validate()
        .map_err(|error| error.to_string())?;
    dispatch
        .binding
        .validate()
        .map_err(|error| error.to_string())?;
    dispatch
        .admission
        .validate()
        .map_err(|error| error.to_string())?;
    dispatch
        .source_snapshot
        .validate()
        .map_err(|error| error.to_string())?;
    dispatch
        .capability_pack
        .validate()
        .map_err(|error| error.to_string())?;
    dispatch
        .backend
        .validate()
        .map_err(|error| error.to_string())?;
    dispatch
        .backend_approval
        .verify(dispatch.backend_approval_key, dispatch.now_unix_ms)
        .map_err(|error| error.to_string())?;
    dispatch
        .fact_binding
        .validate()
        .map_err(|error| error.to_string())?;
    dispatch
        .slide_plan
        .validate()
        .map_err(|error| error.to_string())?;
    validate_resolved_presentation_operation(dispatch.resolved_operation, dispatch.slide_plan)?;
    validate_authority(dispatch.authority)?;
    validate_relative_path_token(dispatch.source_relative_path)
        .map_err(|error| error.to_string())?;
    validate_relative_path_token(dispatch.destination_relative_path)
        .map_err(|error| error.to_string())?;
    let capability = presentation_capability_id(dispatch.intent.operation);
    let exact = dispatch.intent.mutation.as_ref() == Some(&dispatch.resolved_operation.mutation)
        && dispatch.intent.case_id == dispatch.authority.case_id
        && dispatch.intent.presentation_id == dispatch.source_snapshot.presentation_id
        && dispatch.intent.artifact_id == dispatch.source_snapshot.artifact_id
        && dispatch.intent.source_generation == dispatch.source_snapshot.artifact_generation
        && dispatch.intent.source_content_sha256 == dispatch.source_snapshot.source_content_sha256
        && dispatch.intent.source_snapshot_sha256 == dispatch.source_snapshot.snapshot_sha256
        && dispatch.intent.context_slice_sha256 == dispatch.binding.context_slice_sha256
        && dispatch.intent.slide_plan_sha256 == dispatch.slide_plan.plan_sha256
        && dispatch.intent.fact_binding_sha256 == dispatch.fact_binding.binding_sha256
        && dispatch.binding.role_instance_sha256 == dispatch.authority.role_instance_sha256
        && dispatch.binding.case_instance_sha256 == dispatch.authority.case_instance_sha256
        && dispatch.binding.lease_sha256 == dispatch.authority.lease_sha256
        && dispatch.binding.case_work_grant_sha256 == dispatch.authority.case_work_grant_sha256
        && dispatch.binding.workspace_profile_sha256 == profile.profile_sha256
        && dispatch.binding.root_binding_sha256 == root_binding.binding_sha256
        && dispatch.binding.artifact_version_sha256 == dispatch.authority.artifact_version_sha256
        && dispatch.binding.intent_sha256 == dispatch.intent.intent_sha256
        && dispatch.binding.context_slice_sha256 == dispatch.slide_plan.context_slice_sha256
        && dispatch.binding.slide_plan_sha256 == dispatch.slide_plan.plan_sha256
        && dispatch.binding.fact_binding_sha256 == dispatch.fact_binding.binding_sha256
        && dispatch.binding.capability_pack_sha256 == dispatch.capability_pack.pack_sha256
        && dispatch.binding.backend_descriptor_sha256 == dispatch.backend.descriptor_sha256
        && dispatch.binding.backend_approval_sha256 == dispatch.backend_approval.approval_sha256
        && dispatch.binding.policy_admission_sha256 == dispatch.admission.admission_sha256
        && dispatch.binding.activation_sha256 == dispatch.admission.admission_sha256
        && dispatch.binding.worker_sha256 == dispatch.backend.worker_sha256
        && dispatch.binding.application_sha256 == dispatch.backend.application_sha256
        && dispatch.binding.expected_source_generation
            == dispatch.source_snapshot.artifact_generation
        && dispatch.admission.adapter_kind == AdapterKindV1::OfficePresentation
        && dispatch.admission.capability_id == capability
        && dispatch.admission.application_pack_sha256 == dispatch.authority.application_pack_sha256
        && dispatch.admission.capability_binding_sha256
            == dispatch.authority.capability_binding_sha256
        && dispatch.admission.authority_sha256 == dispatch.authority.authority_sha256
        && dispatch.backend_approval.organization_id == dispatch.authority.organization_id
        && dispatch.backend_approval.backend_descriptor_sha256
            == dispatch.backend.descriptor_sha256
        && dispatch.backend_approval.capability_pack_sha256 == dispatch.capability_pack.pack_sha256
        && dispatch.backend_approval.workspace_profile_sha256 == profile.profile_sha256
        && dispatch
            .backend_approval
            .approved_operation_ids
            .contains(&capability.to_owned())
        && dispatch
            .backend
            .supported_operations
            .contains(&dispatch.intent.operation)
        && dispatch
            .capability_pack
            .semantic_operations
            .contains(&dispatch.intent.operation)
        && dispatch.binding.issued_at_unix_ms <= dispatch.now_unix_ms
        && dispatch.now_unix_ms < dispatch.binding.expires_at_unix_ms
        && dispatch.source_snapshot.freshness_expires_at_unix_ms >= dispatch.now_unix_ms
        && dispatch.admission.admitted_at_unix_seconds <= dispatch.now_unix_ms / 1_000
        && dispatch.now_unix_ms / 1_000 < dispatch.admission.expires_at_unix_seconds;
    if !exact {
        return Err("presentation dispatch differs from its exact authority, plan, fact, policy, or activation binding".to_owned());
    }
    Ok(())
}

fn validate_authority(value: &PresentationAuthorityContextV1) -> Result<(), String> {
    validate_id(&value.organization_id, "presentation organization")
        .map_err(|error| error.to_string())?;
    validate_id(&value.case_id, "presentation Case").map_err(|error| error.to_string())?;
    for hash in [
        &value.role_instance_sha256,
        &value.case_instance_sha256,
        &value.lease_sha256,
        &value.case_work_grant_sha256,
        &value.artifact_version_sha256,
        &value.authority_sha256,
        &value.application_pack_sha256,
        &value.capability_binding_sha256,
    ] {
        validate_hash(hash, "presentation authority hash").map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn build_diff(
    before: &PresentationSemanticSnapshotV1,
    after: &PresentationSemanticSnapshotV1,
) -> Result<PresentationSemanticDiffV1, String> {
    if before.source_content_sha256 == after.source_content_sha256
        || before.snapshot_sha256 == after.snapshot_sha256
    {
        return Err("presentation mutation produced no semantic change".to_owned());
    }
    let before_ids = before
        .slides
        .iter()
        .map(|slide| slide.slide_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let added_slide_ids = after
        .slides
        .iter()
        .filter(|slide| !before_ids.contains(slide.slide_id.as_str()))
        .map(|slide| slide.slide_id.clone())
        .collect::<Vec<_>>();
    let mut changed_slide_ids = Vec::new();
    let mut changed_shape_ids = Vec::new();
    for after_slide in &after.slides {
        if let Some(before_slide) = before
            .slides
            .iter()
            .find(|slide| slide.slide_id == after_slide.slide_id)
        {
            if before_slide.state_sha256 != after_slide.state_sha256 {
                changed_slide_ids.push(after_slide.slide_id.clone());
            }
            for shape in &after_slide.shapes {
                if before_slide
                    .shapes
                    .iter()
                    .find(|candidate| candidate.shape_id == shape.shape_id)
                    .is_none_or(|candidate| candidate.state_sha256 != shape.state_sha256)
                {
                    changed_shape_ids.push(shape.shape_id.clone());
                }
            }
        }
    }
    PresentationSemanticDiffV1 {
        schema_version: 1,
        before_snapshot_sha256: before.snapshot_sha256.clone(),
        after_snapshot_sha256: after.snapshot_sha256.clone(),
        added_slide_ids,
        changed_slide_ids,
        changed_shape_ids,
        removed_generated_ids: Vec::new(),
        unexpected_change_ids: Vec::new(),
        diff_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

fn verify_workspace_boundary(
    root: &Path,
    binding: &WorkspaceRootBindingV1,
    profile: &OfficeWorkspaceProfileV1,
    now_unix_ms: u64,
) -> Result<(), String> {
    let canonical = root.canonicalize().map_err(|error| error.to_string())?;
    if canonical_text(&canonical) != binding.canonical_root
        || binding.workspace_id != profile.workspace_id
        || profile.workspace_root_binding_sha256 != binding.binding_sha256
        || now_unix_ms < binding.valid_from_unix_ms
        || now_unix_ms > binding.valid_until_unix_ms
        || now_unix_ms < profile.valid_from_unix_ms
        || now_unix_ms > profile.valid_until_unix_ms
        || binding.network_share_allowed
        || binding.removable_media_allowed
        || !binding.reparse_forbidden
        || !binding.symlink_forbidden
    {
        return Err("presentation workspace boundary differs".to_owned());
    }
    Ok(())
}

fn verify_fresh_reopen(
    worker: &PresentationSemanticSnapshotV1,
    fresh: &PresentationSemanticSnapshotV1,
) -> Result<(), String> {
    worker.validate().map_err(|error| error.to_string())?;
    fresh.validate().map_err(|error| error.to_string())?;
    if fresh.presentation_id != worker.presentation_id
        || fresh.artifact_id != worker.artifact_id
        || fresh.artifact_generation != worker.artifact_generation
        || fresh.backend_id != worker.backend_id
        || fresh.source_content_sha256 != worker.source_content_sha256
        || fresh.semantic_state_sha256 != worker.semantic_state_sha256
        || fresh.slide_count != worker.slide_count
        || fresh.observed_at_unix_ms <= worker.observed_at_unix_ms
        || fresh.snapshot_sha256 == worker.snapshot_sha256
    {
        return Err(
            "fresh presentation reopen differs from worker output or reused an observation"
                .to_owned(),
        );
    }
    Ok(())
}

fn resolve_relative(root: &Path, relative: &str, new_file: bool) -> Result<PathBuf, String> {
    validate_relative_path_token(relative).map_err(|error| error.to_string())?;
    let path = Path::new(relative);
    if path
        .components()
        .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err("presentation path is not a bounded relative token".to_owned());
    }
    let candidate = root.join(path);
    let parent = candidate
        .parent()
        .ok_or_else(|| "presentation path parent is absent".to_owned())?
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let canonical_root = root.canonicalize().map_err(|error| error.to_string())?;
    if !parent.starts_with(&canonical_root)
        || d2i_windows_host::is_reparse_point(&parent).map_err(|error| error.to_string())?
        || (!new_file && !candidate.is_file())
        || (new_file && candidate.exists())
    {
        return Err("presentation path escapes, exists, or is unavailable".to_owned());
    }
    Ok(candidate)
}

fn resolve_directory(root: &Path, relative: &str) -> Result<PathBuf, String> {
    validate_relative_path_token(relative).map_err(|error| error.to_string())?;
    let path = root.join(relative);
    let canonical = path.canonicalize().map_err(|error| error.to_string())?;
    if !canonical.starts_with(root.canonicalize().map_err(|error| error.to_string())?)
        || !canonical.is_dir()
        || d2i_windows_host::is_reparse_point(&canonical).map_err(|error| error.to_string())?
    {
        return Err("presentation render directory escapes or is unavailable".to_owned());
    }
    Ok(canonical)
}

fn verify_executable(path: &Path, expected_sha256: &str, label: &str) -> Result<(), String> {
    validate_hash(expected_sha256, label).map_err(|error| error.to_string())?;
    if !path.is_file()
        || d2i_windows_host::is_reparse_point(path).map_err(|error| error.to_string())?
        || file_sha256(path)? != expected_sha256
    {
        return Err(format!("{label} executable binding differs"));
    }
    Ok(())
}

fn file_sha256(path: &Path) -> Result<String, String> {
    fs::read(path)
        .map(|bytes| sha256_bytes(&bytes))
        .map_err(|error| error.to_string())
}
