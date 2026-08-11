use crate::{ResearchError, ResearchRecoveryActionV1, ResearchRecoveryStageV1};

/// Returns the only admissible recovery action for a durable OFFICE-600 stage.
/// The mapping is closed so a restart cannot silently repeat a network or
/// workspace side effect.
pub fn recovery_action_v1(
    stage: ResearchRecoveryStageV1,
) -> Result<ResearchRecoveryActionV1, ResearchError> {
    let action = match stage {
        ResearchRecoveryStageV1::BeforeAdmission => ResearchRecoveryActionV1::StartFresh,
        ResearchRecoveryStageV1::UrlAdmitted => ResearchRecoveryActionV1::ResumeAdmission,
        ResearchRecoveryStageV1::RequestSent | ResearchRecoveryStageV1::HeadersReceived => {
            ResearchRecoveryActionV1::ReevaluateRequestState
        }
        ResearchRecoveryStageV1::PartialBody => ResearchRecoveryActionV1::DiscardPartialBody,
        ResearchRecoveryStageV1::BodyDurable => ResearchRecoveryActionV1::RecoverDurableBody,
        ResearchRecoveryStageV1::SnapshotDurable => ResearchRecoveryActionV1::ResumeEvidence,
        ResearchRecoveryStageV1::EvidenceDurable => ResearchRecoveryActionV1::ResumeSynthesis,
        ResearchRecoveryStageV1::DownloadDurable => ResearchRecoveryActionV1::ResumeTrustCheck,
        ResearchRecoveryStageV1::AttachmentTrustInProgress => {
            ResearchRecoveryActionV1::ReobserveAttachment
        }
        ResearchRecoveryStageV1::TrustPassed => ResearchRecoveryActionV1::ResumeValidation,
        ResearchRecoveryStageV1::ValidationPassed => ResearchRecoveryActionV1::ResumePromotion,
        ResearchRecoveryStageV1::WorkspacePromoted => {
            ResearchRecoveryActionV1::RepairPromotionReceipt
        }
        ResearchRecoveryStageV1::ReportDurable => ResearchRecoveryActionV1::RepairClosureMetadata,
    };
    Ok(action)
}

pub fn recovery_requires_external_network_v1(stage: ResearchRecoveryStageV1) -> bool {
    matches!(
        stage,
        ResearchRecoveryStageV1::RequestSent | ResearchRecoveryStageV1::HeadersReceived
    )
}

pub fn recovery_may_promote_workspace_v1(stage: ResearchRecoveryStageV1) -> bool {
    matches!(stage, ResearchRecoveryStageV1::ValidationPassed)
}
