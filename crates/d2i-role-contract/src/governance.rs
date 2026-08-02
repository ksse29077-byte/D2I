use crate::contract::{OrganizationScopeV1, RoleContractV1};
use crate::strict::{canonical_json_bytes, hash_without};
use crate::{
    canonicalize_ids, integrity, invalid, validate_evidence, validate_hash, validate_id,
    RoleContractError, MAX_ROLE_TTL_SECONDS, ROLE_CONTRACT_SCHEMA_VERSION,
};
use d2i_cognitive_ir::CognitiveRiskClass;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Signed organizational approval for one exact Role Contract version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleContractApprovalV1 {
    pub schema_version: u32,
    pub approval_id: String,
    pub organization_id: String,
    pub role_contract_id: String,
    pub role_version: String,
    pub contract_sha256: String,
    pub approved_by_actor_id: String,
    pub approver_authority_class: String,
    pub signer_key_id: String,
    pub issued_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub approval_signature: String,
    pub evidence_ids: Vec<String>,
    pub approval_sha256: String,
}

/// Signed delegation of a strict subset of one approved Role Contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleDelegationGrantV1 {
    pub schema_version: u32,
    pub delegation_id: String,
    pub organization_id: String,
    pub role_instance_id: String,
    pub role_contract_id: String,
    pub role_version: String,
    pub contract_sha256: String,
    pub approval_sha256: String,
    pub delegated_scope: OrganizationScopeV1,
    pub delegated_work_class_ids: Vec<String>,
    pub delegated_application_pack_ids: Vec<String>,
    pub delegated_integration_ids: Vec<String>,
    pub delegated_capability_ids: Vec<String>,
    pub autonomous_capability_ids: Vec<String>,
    pub confirmation_capability_ids: Vec<String>,
    pub prohibited_capability_ids: Vec<String>,
    pub maximum_autonomous_risk: CognitiveRiskClass,
    pub maximum_confirmable_risk: CognitiveRiskClass,
    pub policy_set_sha256: String,
    pub valid_from_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub assigned_by_actor_id: String,
    pub signer_key_id: String,
    pub delegation_signature: String,
    pub evidence_ids: Vec<String>,
    pub delegation_sha256: String,
}

/// Seals and signs an approval draft. Signature and self-hash placeholders are replaced.
pub fn create_role_contract_approval(
    mut approval: RoleContractApprovalV1,
    contract: &RoleContractV1,
    signing_key: &SigningKey,
) -> Result<RoleContractApprovalV1, RoleContractError> {
    contract.validate()?;
    approval.evidence_ids.sort();
    approval.approval_signature = "00".repeat(64);
    approval.approval_sha256 = hash_without(&approval, &["approval_sha256"])?;
    approval.validate_against_contract(contract)?;
    approval.approval_signature =
        hex_encode(&signing_key.sign(&approval.signing_bytes()?).to_bytes());
    approval.approval_sha256 = hash_without(&approval, &["approval_sha256"])?;
    approval.validate_against_contract(contract)?;
    Ok(approval)
}

/// Verifies approval shape, exact contract binding, signer ID, lifetime, and signature.
pub fn verify_role_contract_approval(
    approval: &RoleContractApprovalV1,
    contract: &RoleContractV1,
    expected_signer_key_id: &str,
    verifying_key: &VerifyingKey,
    now_unix_seconds: u64,
) -> Result<(), RoleContractError> {
    contract.validate()?;
    approval.validate_against_contract(contract)?;
    validate_id(expected_signer_key_id, "expected approval signer key ID")?;
    if approval.signer_key_id != expected_signer_key_id {
        return integrity("approval signer key ID differs");
    }
    if now_unix_seconds < approval.issued_at_unix_seconds
        || now_unix_seconds >= approval.expires_at_unix_seconds
    {
        return invalid("Role Contract approval is not active");
    }
    let signature = Signature::from_bytes(&hex_decode_array::<64>(&approval.approval_signature)?);
    verifying_key
        .verify(&approval.signing_bytes()?, &signature)
        .map_err(|error| {
            RoleContractError::Integrity(format!("approval signature rejected: {error}"))
        })
}

/// Seals and signs a delegation after strict subset validation.
pub fn create_role_delegation(
    mut delegation: RoleDelegationGrantV1,
    contract: &RoleContractV1,
    approval: &RoleContractApprovalV1,
    signing_key: &SigningKey,
) -> Result<RoleDelegationGrantV1, RoleContractError> {
    delegation.normalize_sets()?;
    delegation.delegation_signature = "00".repeat(64);
    delegation.delegation_sha256 = hash_without(&delegation, &["delegation_sha256"])?;
    delegation.validate_against(contract, approval)?;
    delegation.delegation_signature =
        hex_encode(&signing_key.sign(&delegation.signing_bytes()?).to_bytes());
    delegation.delegation_sha256 = hash_without(&delegation, &["delegation_sha256"])?;
    delegation.validate_against(contract, approval)?;
    Ok(delegation)
}

/// Verifies a signed delegation and all approval/contract subset constraints.
pub fn verify_role_delegation(
    delegation: &RoleDelegationGrantV1,
    contract: &RoleContractV1,
    approval: &RoleContractApprovalV1,
    expected_signer_key_id: &str,
    verifying_key: &VerifyingKey,
    now_unix_seconds: u64,
) -> Result<(), RoleContractError> {
    delegation.validate_against(contract, approval)?;
    validate_id(expected_signer_key_id, "expected delegation signer key ID")?;
    if delegation.signer_key_id != expected_signer_key_id {
        return integrity("delegation signer key ID differs");
    }
    if now_unix_seconds < delegation.valid_from_unix_seconds
        || now_unix_seconds >= delegation.expires_at_unix_seconds
    {
        return invalid("Role delegation is not active");
    }
    let signature =
        Signature::from_bytes(&hex_decode_array::<64>(&delegation.delegation_signature)?);
    verifying_key
        .verify(&delegation.signing_bytes()?, &signature)
        .map_err(|error| {
            RoleContractError::Integrity(format!("delegation signature rejected: {error}"))
        })
}

impl RoleContractApprovalV1 {
    fn validate_against_contract(
        &self,
        contract: &RoleContractV1,
    ) -> Result<(), RoleContractError> {
        if self.schema_version != ROLE_CONTRACT_SCHEMA_VERSION
            || self.issued_at_unix_seconds == 0
            || self.expires_at_unix_seconds <= self.issued_at_unix_seconds
            || self.expires_at_unix_seconds - self.issued_at_unix_seconds > MAX_ROLE_TTL_SECONDS
        {
            return invalid("Role approval schema or lifetime is invalid");
        }
        for (value, label) in [
            (&self.approval_id, "approval_id"),
            (&self.organization_id, "approval organization_id"),
            (&self.role_contract_id, "approval role_contract_id"),
            (&self.role_version, "approval role_version"),
            (&self.approved_by_actor_id, "approved_by_actor_id"),
            (&self.approver_authority_class, "approver_authority_class"),
            (&self.signer_key_id, "approval signer_key_id"),
        ] {
            validate_id(value, label)?;
        }
        validate_hash(&self.contract_sha256, "approval contract_sha256")?;
        validate_evidence(&self.evidence_ids, "approval evidence IDs")?;
        if self.organization_id != contract.organization_scope.organization_id
            || self.role_contract_id != contract.role_contract_id
            || self.role_version != contract.role_version
            || self.contract_sha256 != contract.contract_sha256
        {
            return integrity("approval does not bind the exact Role Contract");
        }
        if self.approval_signature.len() != 128
            || !self
                .approval_signature
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return invalid("approval signature encoding is invalid");
        }
        validate_hash(&self.approval_sha256, "approval_sha256")?;
        if hash_without(self, &["approval_sha256"])? != self.approval_sha256 {
            return integrity("approval_sha256 differs from signed approval");
        }
        Ok(())
    }

    fn signing_bytes(&self) -> Result<Vec<u8>, RoleContractError> {
        let mut value = serde_json::to_value(self)
            .map_err(|error| RoleContractError::Json(error.to_string()))?;
        let object = value.as_object_mut().ok_or_else(|| {
            RoleContractError::Json("approval payload is not an object".to_owned())
        })?;
        object.remove("approval_signature");
        object.remove("approval_sha256");
        canonical_json_bytes(&value)
    }
}

impl RoleDelegationGrantV1 {
    fn normalize_sets(&mut self) -> Result<(), RoleContractError> {
        self.delegated_scope.normalize_for_delegation()?;
        for (values, label, empty) in [
            (
                &mut self.delegated_work_class_ids,
                "delegated work classes",
                false,
            ),
            (
                &mut self.delegated_application_pack_ids,
                "delegated application packs",
                false,
            ),
            (
                &mut self.delegated_integration_ids,
                "delegated integrations",
                false,
            ),
            (
                &mut self.delegated_capability_ids,
                "delegated capabilities",
                false,
            ),
            (
                &mut self.autonomous_capability_ids,
                "delegated autonomous capabilities",
                true,
            ),
            (
                &mut self.confirmation_capability_ids,
                "delegated confirmation capabilities",
                true,
            ),
            (
                &mut self.prohibited_capability_ids,
                "delegated prohibited capabilities",
                true,
            ),
            (&mut self.evidence_ids, "delegation evidence IDs", false),
        ] {
            canonicalize_ids(values, label, empty)?;
        }
        Ok(())
    }

    /// Validates the delegation as a strict subset of contract and approval.
    pub fn validate_against(
        &self,
        contract: &RoleContractV1,
        approval: &RoleContractApprovalV1,
    ) -> Result<(), RoleContractError> {
        contract.validate()?;
        approval.validate_against_contract(contract)?;
        if self.schema_version != ROLE_CONTRACT_SCHEMA_VERSION
            || self.valid_from_unix_seconds == 0
            || self.expires_at_unix_seconds <= self.valid_from_unix_seconds
            || self.valid_from_unix_seconds < approval.issued_at_unix_seconds
            || self.expires_at_unix_seconds > approval.expires_at_unix_seconds
        {
            return invalid("Role delegation schema or validity intersection is invalid");
        }
        for (value, label) in [
            (&self.delegation_id, "delegation_id"),
            (&self.organization_id, "delegation organization_id"),
            (&self.role_instance_id, "role_instance_id"),
            (&self.role_contract_id, "delegation role_contract_id"),
            (&self.role_version, "delegation role_version"),
            (&self.assigned_by_actor_id, "assigned_by_actor_id"),
            (&self.signer_key_id, "delegation signer_key_id"),
        ] {
            validate_id(value, label)?;
        }
        for (hash, label) in [
            (&self.contract_sha256, "delegation contract_sha256"),
            (&self.approval_sha256, "delegation approval_sha256"),
            (&self.policy_set_sha256, "delegation policy_set_sha256"),
        ] {
            validate_hash(hash, label)?;
        }
        self.delegated_scope.validate()?;
        for (values, label, empty) in [
            (
                &self.delegated_work_class_ids,
                "delegated work classes",
                false,
            ),
            (
                &self.delegated_application_pack_ids,
                "delegated application packs",
                false,
            ),
            (
                &self.delegated_integration_ids,
                "delegated integrations",
                false,
            ),
            (
                &self.delegated_capability_ids,
                "delegated capabilities",
                false,
            ),
            (
                &self.autonomous_capability_ids,
                "delegated autonomous capabilities",
                true,
            ),
            (
                &self.confirmation_capability_ids,
                "delegated confirmation capabilities",
                true,
            ),
            (
                &self.prohibited_capability_ids,
                "delegated prohibited capabilities",
                true,
            ),
        ] {
            crate::validate_ids(values, label, empty)?;
        }
        validate_evidence(&self.evidence_ids, "delegation evidence IDs")?;
        if self.organization_id != contract.organization_scope.organization_id
            || self.role_contract_id != contract.role_contract_id
            || self.role_version != contract.role_version
            || self.contract_sha256 != contract.contract_sha256
            || self.approval_sha256 != approval.approval_sha256
            || self.policy_set_sha256 != contract.policy_set_sha256
            || self.maximum_autonomous_risk > contract.risk_policy.maximum_autonomous_risk
            || self.maximum_confirmable_risk > contract.risk_policy.maximum_confirmable_risk
            || self.maximum_autonomous_risk > self.maximum_confirmable_risk
            || !self
                .delegated_scope
                .is_subset_of(&contract.organization_scope)
        {
            return invalid("delegation identity, scope, policy, or risk exceeds contract maximum");
        }
        let contract_work = contract
            .accepted_work_classes
            .iter()
            .map(|item| item.work_class_id.clone())
            .collect::<BTreeSet<_>>();
        let contract_apps = contract
            .application_bindings
            .iter()
            .map(|item| item.application_pack_id.clone())
            .collect::<BTreeSet<_>>();
        let contract_integrations = contract
            .application_bindings
            .iter()
            .flat_map(|item| item.integration_ids.iter().cloned())
            .collect::<BTreeSet<_>>();
        let contract_caps = set(&contract.capability_policy.allowed_capability_ids);
        let delegated_caps = set(&self.delegated_capability_ids);
        let autonomous = set(&self.autonomous_capability_ids);
        let confirmation = set(&self.confirmation_capability_ids);
        let prohibited = set(&self.prohibited_capability_ids);
        if !set(&self.delegated_work_class_ids).is_subset(&contract_work)
            || !set(&self.delegated_application_pack_ids).is_subset(&contract_apps)
            || !set(&self.delegated_integration_ids).is_subset(&contract_integrations)
            || !delegated_caps.is_subset(&contract_caps)
            || !autonomous.is_subset(&delegated_caps)
            || !confirmation.is_subset(&delegated_caps)
            || !prohibited.is_subset(&set(&contract.capability_policy.prohibited_capability_ids))
            || !autonomous.is_disjoint(&confirmation)
            || !delegated_caps.is_disjoint(&prohibited)
        {
            return invalid(
                "delegation work, application, integration, or capability expansion detected",
            );
        }
        if self.delegation_signature.len() != 128
            || !self
                .delegation_signature
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return invalid("delegation signature encoding is invalid");
        }
        validate_hash(&self.delegation_sha256, "delegation_sha256")?;
        if hash_without(self, &["delegation_sha256"])? != self.delegation_sha256 {
            return integrity("delegation_sha256 differs from signed delegation");
        }
        Ok(())
    }

    fn signing_bytes(&self) -> Result<Vec<u8>, RoleContractError> {
        let mut value = serde_json::to_value(self)
            .map_err(|error| RoleContractError::Json(error.to_string()))?;
        let object = value.as_object_mut().ok_or_else(|| {
            RoleContractError::Json("delegation payload is not an object".to_owned())
        })?;
        object.remove("delegation_signature");
        object.remove("delegation_sha256");
        canonical_json_bytes(&value)
    }
}

impl OrganizationScopeV1 {
    pub(crate) fn normalize_for_delegation(&mut self) -> Result<(), RoleContractError> {
        for (values, label) in [
            (&mut self.business_unit_ids, "delegated business units"),
            (&mut self.site_ids, "delegated sites"),
            (&mut self.domain_ids, "delegated domains"),
            (&mut self.environment_ids, "delegated environments"),
            (&mut self.jurisdiction_ids, "delegated jurisdictions"),
        ] {
            canonicalize_ids(values, label, true)?;
        }
        self.validate()
    }
}

fn set(values: &[String]) -> BTreeSet<String> {
    values.iter().cloned().collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn hex_decode_array<const N: usize>(value: &str) -> Result<[u8; N], RoleContractError> {
    if value.len() != N * 2 {
        return invalid("signature hex length differs");
    }
    let mut bytes = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(bytes)
}

fn hex_nibble(value: u8) -> Result<u8, RoleContractError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => invalid("signature contains non-lowercase-hex data"),
    }
}
