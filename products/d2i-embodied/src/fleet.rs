use crate::{
    hex_decode_array, hex_encode, json_bytes, sha256_bytes, validate_hash, validate_text,
    validate_token, EmbodiedError,
};
use d2i_compiler::verify_package;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

/// External package-signature verification evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageSignatureAttestation {
    pub verifier_id: String,
    pub signature_scheme: String,
    pub package_content_hash: String,
    pub verified_at_unix_seconds: u64,
    pub verified: bool,
}

/// Required simulation evidence for a fleet rollout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimulationQualification {
    pub simulation_id: String,
    pub source_build_id: String,
    pub source_package_content_hash: String,
    pub replay_hash: String,
    pub matched: bool,
    pub critical_failure_count: u64,
}

/// One cumulative staged-rollout cohort.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetCohort {
    pub cohort_id: String,
    pub cumulative_percent: u8,
    pub robot_classes: BTreeSet<String>,
    pub observation_seconds: u64,
}

/// Human approval for a fleet rollout plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetApproval {
    pub approver_id: String,
    pub approved_at_unix_seconds: u64,
    pub rationale: String,
}

/// Inputs bound to a verified immutable package before signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetPromotionInput {
    pub fleet_id: String,
    pub rollout_id: String,
    pub created_at_unix_seconds: u64,
    pub hardware_profile_hashes: Vec<String>,
    pub safety_controller_contract_id: String,
    pub package_signature: PackageSignatureAttestation,
    pub simulation: SimulationQualification,
    pub cohorts: Vec<FleetCohort>,
    pub rollback_build_id: String,
    pub rollback_package_content_hash: String,
    pub approval: FleetApproval,
}

/// Signed authorization metadata. It does not perform deployment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetPromotionRecord {
    pub schema_version: u32,
    pub state: String,
    pub fleet_id: String,
    pub rollout_id: String,
    pub created_at_unix_seconds: u64,
    pub build_id: String,
    pub package_content_hash: String,
    pub hardware_profile_hashes: Vec<String>,
    pub safety_controller_contract_id: String,
    pub package_signature: PackageSignatureAttestation,
    pub simulation: SimulationQualification,
    pub cohorts: Vec<FleetCohort>,
    pub rollback_build_id: String,
    pub rollback_package_content_hash: String,
    pub approval: FleetApproval,
    pub signer_public_key: String,
    pub signature: String,
    pub record_hash: String,
}

#[derive(Serialize)]
struct SignedPayload<'a> {
    schema_version: u32,
    state: &'a str,
    fleet_id: &'a str,
    rollout_id: &'a str,
    created_at_unix_seconds: u64,
    build_id: &'a str,
    package_content_hash: &'a str,
    hardware_profile_hashes: &'a [String],
    safety_controller_contract_id: &'a str,
    package_signature: &'a PackageSignatureAttestation,
    simulation: &'a SimulationQualification,
    cohorts: &'a [FleetCohort],
    rollback_build_id: &'a str,
    rollback_package_content_hash: &'a str,
    approval: &'a FleetApproval,
    signer_public_key: &'a str,
}

#[derive(Serialize)]
struct RecordHashPayload<'a> {
    signed: SignedPayload<'a>,
    signature: &'a str,
}

/// Creates a signed staged-rollout authorization without contacting a fleet.
pub fn create_fleet_promotion(
    package_root: &Path,
    rollback_package_root: &Path,
    input: FleetPromotionInput,
    secret_key: [u8; 32],
) -> Result<FleetPromotionRecord, EmbodiedError> {
    let package =
        verify_package(package_root).map_err(|error| EmbodiedError::Package(error.to_string()))?;
    let rollback = verify_package(rollback_package_root)
        .map_err(|error| EmbodiedError::Package(error.to_string()))?;
    validate_input(&input, &package.build_id, &package.package_content_hash)?;
    if package.build_id == rollback.build_id
        && package.package_content_hash == rollback.package_content_hash
    {
        return Err(EmbodiedError::Invalid(
            "rollback package must differ from the rollout package".to_owned(),
        ));
    }
    if input.rollback_build_id != rollback.build_id
        || input.rollback_package_content_hash != rollback.package_content_hash
    {
        return Err(EmbodiedError::Integrity(
            "rollback identity does not match the verified rollback package".to_owned(),
        ));
    }
    let signing_key = SigningKey::from_bytes(&secret_key);
    let signer_public_key = hex_encode(&signing_key.verifying_key().to_bytes());
    let state = "approved_for_staged_rollout".to_owned();
    let payload = SignedPayload {
        schema_version: 1,
        state: &state,
        fleet_id: &input.fleet_id,
        rollout_id: &input.rollout_id,
        created_at_unix_seconds: input.created_at_unix_seconds,
        build_id: &package.build_id,
        package_content_hash: &package.package_content_hash,
        hardware_profile_hashes: &input.hardware_profile_hashes,
        safety_controller_contract_id: &input.safety_controller_contract_id,
        package_signature: &input.package_signature,
        simulation: &input.simulation,
        cohorts: &input.cohorts,
        rollback_build_id: &input.rollback_build_id,
        rollback_package_content_hash: &input.rollback_package_content_hash,
        approval: &input.approval,
        signer_public_key: &signer_public_key,
    };
    let signature = hex_encode(&signing_key.sign(&json_bytes(&payload)?).to_bytes());
    let record_hash = sha256_bytes(&json_bytes(&RecordHashPayload {
        signed: payload,
        signature: &signature,
    })?);
    Ok(FleetPromotionRecord {
        schema_version: 1,
        state,
        fleet_id: input.fleet_id,
        rollout_id: input.rollout_id,
        created_at_unix_seconds: input.created_at_unix_seconds,
        build_id: package.build_id,
        package_content_hash: package.package_content_hash,
        hardware_profile_hashes: input.hardware_profile_hashes,
        safety_controller_contract_id: input.safety_controller_contract_id,
        package_signature: input.package_signature,
        simulation: input.simulation,
        cohorts: input.cohorts,
        rollback_build_id: input.rollback_build_id,
        rollback_package_content_hash: input.rollback_package_content_hash,
        approval: input.approval,
        signer_public_key,
        signature,
        record_hash,
    })
}

/// Verifies rollout semantics, Ed25519 signature, and record hash.
pub fn verify_fleet_promotion(record: &FleetPromotionRecord) -> Result<(), EmbodiedError> {
    let input = FleetPromotionInput {
        fleet_id: record.fleet_id.clone(),
        rollout_id: record.rollout_id.clone(),
        created_at_unix_seconds: record.created_at_unix_seconds,
        hardware_profile_hashes: record.hardware_profile_hashes.clone(),
        safety_controller_contract_id: record.safety_controller_contract_id.clone(),
        package_signature: record.package_signature.clone(),
        simulation: record.simulation.clone(),
        cohorts: record.cohorts.clone(),
        rollback_build_id: record.rollback_build_id.clone(),
        rollback_package_content_hash: record.rollback_package_content_hash.clone(),
        approval: record.approval.clone(),
    };
    if record.schema_version != 1 || record.state != "approved_for_staged_rollout" {
        return Err(EmbodiedError::Integrity(
            "fleet promotion state or schema is invalid".to_owned(),
        ));
    }
    validate_input(&input, &record.build_id, &record.package_content_hash)?;
    validate_token(&record.build_id, "build_id")?;
    let payload = signed_payload(record);
    let public_bytes = hex_decode_array::<32>(&record.signer_public_key)?;
    let signature_bytes = hex_decode_array::<64>(&record.signature)?;
    let verifying_key = VerifyingKey::from_bytes(&public_bytes)
        .map_err(|error| EmbodiedError::Signature(error.to_string()))?;
    verifying_key
        .verify_strict(
            &json_bytes(&payload)?,
            &Signature::from_bytes(&signature_bytes),
        )
        .map_err(|error| EmbodiedError::Signature(error.to_string()))?;
    let expected_hash = sha256_bytes(&json_bytes(&RecordHashPayload {
        signed: payload,
        signature: &record.signature,
    })?);
    if expected_hash != record.record_hash {
        return Err(EmbodiedError::Integrity(
            "fleet promotion record hash mismatch".to_owned(),
        ));
    }
    Ok(())
}

fn validate_input(
    input: &FleetPromotionInput,
    build_id: &str,
    package_content_hash: &str,
) -> Result<(), EmbodiedError> {
    validate_token(&input.fleet_id, "fleet_id")?;
    validate_token(&input.rollout_id, "rollout_id")?;
    validate_token(
        &input.safety_controller_contract_id,
        "safety_controller_contract_id",
    )?;
    validate_token(&input.rollback_build_id, "rollback_build_id")?;
    validate_hash(
        &input.rollback_package_content_hash,
        "rollback_package_content_hash",
    )?;
    validate_token(&input.package_signature.verifier_id, "verifier_id")?;
    validate_text(
        &input.package_signature.signature_scheme,
        "signature_scheme",
    )?;
    validate_hash(
        &input.package_signature.package_content_hash,
        "attested package hash",
    )?;
    validate_token(&input.simulation.simulation_id, "simulation_id")?;
    validate_token(
        &input.simulation.source_build_id,
        "simulation source_build_id",
    )?;
    validate_hash(
        &input.simulation.source_package_content_hash,
        "simulation source_package_content_hash",
    )?;
    validate_hash(&input.simulation.replay_hash, "simulation replay_hash")?;
    validate_token(&input.approval.approver_id, "approver_id")?;
    validate_text(&input.approval.rationale, "approval rationale")?;
    if input.created_at_unix_seconds == 0
        || input.package_signature.verified_at_unix_seconds == 0
        || !input.package_signature.verified
        || input.package_signature.package_content_hash != package_content_hash
        || input.simulation.source_build_id != build_id
        || input.simulation.source_package_content_hash != package_content_hash
        || !input.simulation.matched
        || input.simulation.critical_failure_count != 0
        || input.approval.approved_at_unix_seconds < input.created_at_unix_seconds
        || input.approval.approved_at_unix_seconds
            < input.package_signature.verified_at_unix_seconds
        || input.hardware_profile_hashes.is_empty()
        || input.hardware_profile_hashes.len() > 10_000
        || input.cohorts.is_empty()
        || input.cohorts.len() > 100
    {
        return Err(EmbodiedError::Invalid(
            "fleet promotion evidence or approval is incomplete".to_owned(),
        ));
    }
    for hash in &input.hardware_profile_hashes {
        validate_hash(hash, "hardware_profile_hash")?;
    }
    if input
        .hardware_profile_hashes
        .windows(2)
        .any(|window| window[0] >= window[1])
    {
        return Err(EmbodiedError::Invalid(
            "hardware profile hashes must be unique and sorted".to_owned(),
        ));
    }
    let mut previous_percent = 0_u8;
    let mut cohort_ids = BTreeSet::new();
    for cohort in &input.cohorts {
        validate_token(&cohort.cohort_id, "cohort_id")?;
        if cohort.cumulative_percent <= previous_percent
            || cohort.cumulative_percent > 100
            || cohort.robot_classes.is_empty()
            || cohort.observation_seconds == 0
            || !cohort_ids.insert(cohort.cohort_id.clone())
        {
            return Err(EmbodiedError::Invalid(
                "fleet cohorts must be unique, bounded, and strictly staged".to_owned(),
            ));
        }
        previous_percent = cohort.cumulative_percent;
    }
    if previous_percent != 100 {
        return Err(EmbodiedError::Invalid(
            "final fleet cohort must reach 100 percent".to_owned(),
        ));
    }
    Ok(())
}

fn signed_payload(record: &FleetPromotionRecord) -> SignedPayload<'_> {
    SignedPayload {
        schema_version: record.schema_version,
        state: &record.state,
        fleet_id: &record.fleet_id,
        rollout_id: &record.rollout_id,
        created_at_unix_seconds: record.created_at_unix_seconds,
        build_id: &record.build_id,
        package_content_hash: &record.package_content_hash,
        hardware_profile_hashes: &record.hardware_profile_hashes,
        safety_controller_contract_id: &record.safety_controller_contract_id,
        package_signature: &record.package_signature,
        simulation: &record.simulation,
        cohorts: &record.cohorts,
        rollback_build_id: &record.rollback_build_id,
        rollback_package_content_hash: &record.rollback_package_content_hash,
        approval: &record.approval,
        signer_public_key: &record.signer_public_key,
    }
}
