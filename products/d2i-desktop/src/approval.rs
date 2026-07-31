use crate::{
    hash_value, hex_decode_array, hex_encode, validate_hash, validate_token, DesktopError,
    DesktopPolicy, PolicyDecision, PolicyDecisionStatus, PreparedAction,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Signed human approval bound to one prepared action and one policy decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanApproval {
    pub schema_version: u32,
    pub approval_id: String,
    pub approver_id: String,
    pub action_hash: String,
    pub policy_decision_hash: String,
    pub preparation_hash: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub nonce: String,
    pub signature_hex: String,
}

#[derive(Serialize)]
struct UnsignedApproval<'a> {
    schema_version: u32,
    approval_id: &'a str,
    approver_id: &'a str,
    action_hash: &'a str,
    policy_decision_hash: &'a str,
    preparation_hash: &'a str,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    nonce: &'a str,
}

/// Creates an Ed25519 approval. Key custody remains outside this product.
#[allow(clippy::too_many_arguments)]
pub fn sign_approval(
    approval_id: String,
    approver_id: String,
    decision: &PolicyDecision,
    prepared: &PreparedAction,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    nonce: String,
    signing_key: &SigningKey,
) -> Result<HumanApproval, DesktopError> {
    if decision.status != PolicyDecisionStatus::ApprovalRequired {
        return Err(DesktopError::Approval(
            "approval may only sign an approval-required policy decision".to_owned(),
        ));
    }
    validate_token(&approval_id, "approval_id")?;
    validate_token(&approver_id, "approver_id")?;
    validate_token(&nonce, "approval nonce")?;
    if issued_at_unix_ms >= expires_at_unix_ms || expires_at_unix_ms > prepared.expires_at_unix_ms {
        return Err(DesktopError::Approval(
            "approval lifetime is invalid or exceeds preparation expiry".to_owned(),
        ));
    }
    let policy_decision_hash = decision.decision_hash()?;
    let unsigned = UnsignedApproval {
        schema_version: 1,
        approval_id: &approval_id,
        approver_id: &approver_id,
        action_hash: &decision.action_hash,
        policy_decision_hash: &policy_decision_hash,
        preparation_hash: &prepared.preparation_hash,
        issued_at_unix_ms,
        expires_at_unix_ms,
        nonce: &nonce,
    };
    let message =
        serde_json::to_vec(&unsigned).map_err(|error| DesktopError::Json(error.to_string()))?;
    let signature = signing_key.sign(&message);
    Ok(HumanApproval {
        schema_version: 1,
        approval_id,
        approver_id,
        action_hash: decision.action_hash.clone(),
        policy_decision_hash,
        preparation_hash: prepared.preparation_hash.clone(),
        issued_at_unix_ms,
        expires_at_unix_ms,
        nonce,
        signature_hex: hex_encode(&signature.to_bytes()),
    })
}

/// Opaque, short-lived permit checked again by the adapter at commit.
#[derive(Debug, Clone)]
pub struct ExecutionPermit {
    action_hash: String,
    policy_decision_hash: String,
    preparation_hash: String,
    adapter_descriptor_hash: String,
    expires_at_unix_ms: u64,
    permit_hash: String,
    approval_id: Option<String>,
}

impl ExecutionPermit {
    /// Returns the permit digest recorded in the audit ledger.
    #[must_use]
    pub fn permit_hash(&self) -> &str {
        &self.permit_hash
    }

    /// Returns the approval identifier when human approval was required.
    #[must_use]
    pub fn approval_id(&self) -> Option<&str> {
        self.approval_id.as_deref()
    }

    pub(crate) fn validate_binding(
        &self,
        action_hash: &str,
        prepared: &PreparedAction,
        now_unix_ms: u64,
    ) -> Result<(), DesktopError> {
        if now_unix_ms > self.expires_at_unix_ms
            || self.action_hash != action_hash
            || self.preparation_hash != prepared.preparation_hash
            || self.adapter_descriptor_hash != prepared.adapter_descriptor_hash
        {
            return Err(DesktopError::Approval(
                "execution permit is expired or bound to different inputs".to_owned(),
            ));
        }
        validate_hash(&self.policy_decision_hash, "permit policy decision hash")?;
        Ok(())
    }
}

#[derive(Serialize)]
struct CognitivePermitDigest<'a> {
    authority_kind: &'static str,
    action_hash: &'a str,
    bound_action_sha256: &'a str,
    policy_decision_sha256: &'a str,
    cognitive_admission_sha256: &'a str,
    preparation_hash: &'a str,
    adapter_descriptor_sha256: &'a str,
    activation_record_hash: &'a str,
    target_resolution_sha256: &'a str,
    input_material_proof_sha256: Option<&'a str>,
    expires_at_unix_ms: u64,
}

/// Mints the opaque legacy adapter permit from an exact Cognitive binding.
///
/// This is additive: the legacy permit digest and human-approval path are
/// unchanged, while adapters continue checking action, preparation, descriptor,
/// and expiry at commit time.
#[allow(clippy::too_many_arguments)]
pub(crate) fn authorize_cognitive_prepared(
    action_hash: &str,
    bound_action_sha256: &str,
    policy_decision_sha256: &str,
    cognitive_admission_sha256: &str,
    prepared: &PreparedAction,
    adapter_descriptor_sha256: &str,
    activation_record_hash: &str,
    target_resolution_sha256: &str,
    input_material_proof_sha256: Option<&str>,
    expires_at_unix_ms: u64,
    now_unix_ms: u64,
) -> Result<ExecutionPermit, DesktopError> {
    prepared.validate()?;
    for (value, label) in [
        (action_hash, "cognitive permit action_hash"),
        (bound_action_sha256, "cognitive permit bound_action_sha256"),
        (
            policy_decision_sha256,
            "cognitive permit policy_decision_sha256",
        ),
        (
            cognitive_admission_sha256,
            "cognitive permit admission_sha256",
        ),
        (
            adapter_descriptor_sha256,
            "cognitive permit adapter_descriptor_sha256",
        ),
        (
            activation_record_hash,
            "cognitive permit activation_record_hash",
        ),
        (
            target_resolution_sha256,
            "cognitive permit target_resolution_sha256",
        ),
    ] {
        validate_hash(value, label)?;
    }
    if let Some(hash) = input_material_proof_sha256 {
        validate_hash(hash, "cognitive permit input_material_proof_sha256")?;
    }
    if prepared.action_hash != action_hash
        || prepared.adapter_descriptor_hash != adapter_descriptor_sha256
        || now_unix_ms < prepared.prepared_at_unix_ms
        || now_unix_ms >= expires_at_unix_ms
        || expires_at_unix_ms > prepared.expires_at_unix_ms
    {
        return Err(DesktopError::Approval(
            "Cognitive permit inputs are expired or differ from preparation".to_owned(),
        ));
    }
    let digest = CognitivePermitDigest {
        authority_kind: "cognitive_activation_admission_v1",
        action_hash,
        bound_action_sha256,
        policy_decision_sha256,
        cognitive_admission_sha256,
        preparation_hash: &prepared.preparation_hash,
        adapter_descriptor_sha256,
        activation_record_hash,
        target_resolution_sha256,
        input_material_proof_sha256,
        expires_at_unix_ms,
    };
    let permit_hash = hash_value(&digest)?;
    Ok(ExecutionPermit {
        action_hash: action_hash.to_owned(),
        policy_decision_hash: policy_decision_sha256.to_owned(),
        preparation_hash: prepared.preparation_hash.clone(),
        adapter_descriptor_hash: adapter_descriptor_sha256.to_owned(),
        expires_at_unix_ms,
        permit_hash,
        approval_id: None,
    })
}

#[derive(Serialize)]
struct PermitDigest<'a> {
    action_hash: &'a str,
    policy_decision_hash: &'a str,
    preparation_hash: &'a str,
    adapter_descriptor_hash: &'a str,
    expires_at_unix_ms: u64,
    approval_id: Option<&'a str>,
}

/// Mints a permit only after exact policy, preparation, time, and signature checks.
pub(crate) fn authorize_prepared(
    policy: &DesktopPolicy,
    decision: &PolicyDecision,
    prepared: &PreparedAction,
    approval: Option<&HumanApproval>,
    now_unix_ms: u64,
) -> Result<ExecutionPermit, DesktopError> {
    policy.validate()?;
    prepared.validate()?;
    let expected_status = if policy.approval_required_for.contains(&decision.risk_class) {
        PolicyDecisionStatus::ApprovalRequired
    } else {
        PolicyDecisionStatus::Allowed
    };
    if decision.status == PolicyDecisionStatus::Denied
        || decision.status != expected_status
        || decision.policy_hash != policy.policy_hash()?
        || decision.action_hash != prepared.action_hash
        || decision.adapter_descriptor_hash != prepared.adapter_descriptor_hash
        || now_unix_ms < prepared.prepared_at_unix_ms
        || now_unix_ms > prepared.expires_at_unix_ms
    {
        return Err(DesktopError::Approval(
            "policy decision and preparation cannot authorize execution".to_owned(),
        ));
    }
    let policy_decision_hash = decision.decision_hash()?;
    let approval_id = match decision.status {
        PolicyDecisionStatus::Allowed => {
            if approval.is_some() {
                return Err(DesktopError::Approval(
                    "unexpected approval for directly allowed action".to_owned(),
                ));
            }
            None
        }
        PolicyDecisionStatus::ApprovalRequired => {
            let approval = approval
                .ok_or_else(|| DesktopError::Approval("human approval is required".to_owned()))?;
            verify_approval(
                policy,
                decision,
                prepared,
                approval,
                now_unix_ms,
                &policy_decision_hash,
            )?;
            Some(approval.approval_id.clone())
        }
        PolicyDecisionStatus::Denied => {
            return Err(DesktopError::Approval(
                "denied action cannot receive a permit".to_owned(),
            ));
        }
    };
    let expires_at_unix_ms = prepared.expires_at_unix_ms.min(
        approval
            .map(|value| value.expires_at_unix_ms)
            .unwrap_or(prepared.expires_at_unix_ms),
    );
    let digest = PermitDigest {
        action_hash: &prepared.action_hash,
        policy_decision_hash: &policy_decision_hash,
        preparation_hash: &prepared.preparation_hash,
        adapter_descriptor_hash: &prepared.adapter_descriptor_hash,
        expires_at_unix_ms,
        approval_id: approval_id.as_deref(),
    };
    let permit_hash = hash_value(&digest)?;
    Ok(ExecutionPermit {
        action_hash: prepared.action_hash.clone(),
        policy_decision_hash,
        preparation_hash: prepared.preparation_hash.clone(),
        adapter_descriptor_hash: prepared.adapter_descriptor_hash.clone(),
        expires_at_unix_ms,
        permit_hash,
        approval_id,
    })
}

fn verify_approval(
    policy: &DesktopPolicy,
    decision: &PolicyDecision,
    prepared: &PreparedAction,
    approval: &HumanApproval,
    now_unix_ms: u64,
    policy_decision_hash: &str,
) -> Result<(), DesktopError> {
    if approval.schema_version != 1 {
        return Err(DesktopError::Approval(
            "approval schema_version must be 1".to_owned(),
        ));
    }
    validate_token(&approval.approval_id, "approval_id")?;
    validate_token(&approval.approver_id, "approver_id")?;
    validate_token(&approval.nonce, "approval nonce")?;
    if approval.action_hash != decision.action_hash
        || approval.policy_decision_hash != policy_decision_hash
        || approval.preparation_hash != prepared.preparation_hash
        || approval.issued_at_unix_ms > now_unix_ms
        || now_unix_ms > approval.expires_at_unix_ms
        || approval.expires_at_unix_ms > prepared.expires_at_unix_ms
    {
        return Err(DesktopError::Approval(
            "approval is expired or bound to different inputs".to_owned(),
        ));
    }
    let public_key = policy
        .approver_public_keys
        .get(&approval.approver_id)
        .ok_or_else(|| DesktopError::Approval("approver is not pinned by policy".to_owned()))?;
    let verifying_key = VerifyingKey::from_bytes(&hex_decode_array::<32>(public_key)?)
        .map_err(|error| DesktopError::Approval(error.to_string()))?;
    let signature = Signature::from_bytes(&hex_decode_array::<64>(&approval.signature_hex)?);
    let unsigned = UnsignedApproval {
        schema_version: approval.schema_version,
        approval_id: &approval.approval_id,
        approver_id: &approval.approver_id,
        action_hash: &approval.action_hash,
        policy_decision_hash: &approval.policy_decision_hash,
        preparation_hash: &approval.preparation_hash,
        issued_at_unix_ms: approval.issued_at_unix_ms,
        expires_at_unix_ms: approval.expires_at_unix_ms,
        nonce: &approval.nonce,
    };
    let message =
        serde_json::to_vec(&unsigned).map_err(|error| DesktopError::Json(error.to_string()))?;
    verifying_key
        .verify(&message, &signature)
        .map_err(|error| DesktopError::Approval(error.to_string()))
}
