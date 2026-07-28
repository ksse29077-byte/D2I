use crate::approval::authorize_prepared;
use crate::{
    evaluate_policy, sha256_bytes, ActionOutcomeStatus, AdapterExecution, AuditEvent,
    AuditEventKind, AuditLedger, DesktopActionIntent, DesktopActor, DesktopAdapter, DesktopError,
    DesktopPolicy, HumanApproval, PolicyDecision, PolicyDecisionStatus, PreparedAction,
};
use d2i_runtime_api::DecisionEnvelope;
use std::collections::BTreeSet;

/// Side-effect-free result returned for human review before commit.
#[derive(Debug, Clone)]
pub struct DesktopActionPreparation {
    pub policy_decision: PolicyDecision,
    pub prepared: PreparedAction,
}

/// Stateful session coordinator that is the only supported commit path.
pub struct DesktopExecutor<A> {
    adapter: A,
    policy: DesktopPolicy,
    actor: DesktopActor,
    session_id: String,
    next_sequence: u64,
    pending_preparation_hash: Option<String>,
    pending_policy_decision_hash: Option<String>,
    consumed_action_ids: BTreeSet<String>,
    consumed_approval_ids: BTreeSet<String>,
    action_count: u32,
    poisoned: bool,
}

impl<A: DesktopAdapter> DesktopExecutor<A> {
    /// Creates a fresh ordered desktop session.
    pub fn new(
        adapter: A,
        policy: DesktopPolicy,
        actor: DesktopActor,
        session_id: String,
    ) -> Result<Self, DesktopError> {
        policy.validate()?;
        actor.validate()?;
        crate::validate_token(&session_id, "desktop session_id")?;
        adapter.descriptor().validate()?;
        Ok(Self {
            adapter,
            policy,
            actor,
            session_id,
            next_sequence: 1,
            pending_preparation_hash: None,
            pending_policy_decision_hash: None,
            consumed_action_ids: BTreeSet::new(),
            consumed_approval_ids: BTreeSet::new(),
            action_count: 0,
            poisoned: false,
        })
    }

    /// Returns the owned adapter after the session is complete.
    pub fn into_adapter(self) -> A {
        self.adapter
    }

    /// Captures policy and adapter preconditions without performing a side effect.
    pub fn prepare(
        &mut self,
        intent: &DesktopActionIntent,
        decision_envelope: &DecisionEnvelope,
        now_unix_ms: u64,
        audit: &mut AuditLedger,
    ) -> Result<DesktopActionPreparation, DesktopError> {
        self.validate_session(intent, decision_envelope, now_unix_ms, audit)?;
        if self.pending_preparation_hash.is_some() {
            return Err(DesktopError::Replay(
                "session already has a pending preparation".to_owned(),
            ));
        }
        let policy_decision =
            evaluate_policy(&self.policy, &self.actor, self.adapter.descriptor(), intent)?;
        if policy_decision.status == PolicyDecisionStatus::Denied {
            self.audit_terminal_without_commit(
                audit,
                AuditEventKind::Denied,
                intent,
                &policy_decision,
                now_unix_ms,
                "policy denied action",
            )?;
            self.consume(intent, None)?;
            return Err(DesktopError::AccessDenied(
                policy_decision.reasons.join("; "),
            ));
        }
        let prepared = self.adapter.prepare(intent, now_unix_ms)?;
        self.pending_preparation_hash = Some(prepared.preparation_hash.clone());
        self.pending_policy_decision_hash = Some(policy_decision.decision_hash()?);
        Ok(DesktopActionPreparation {
            policy_decision,
            prepared,
        })
    }

    /// Commits one previously prepared action after optional human approval.
    #[allow(clippy::too_many_arguments)]
    pub fn commit(
        &mut self,
        intent: &DesktopActionIntent,
        preparation: &DesktopActionPreparation,
        approval: Option<&HumanApproval>,
        payload: Option<&[u8]>,
        now_unix_ms: u64,
        audit: &mut AuditLedger,
    ) -> Result<AdapterExecution, DesktopError> {
        if intent.session_id != self.session_id
            || intent.sequence != self.next_sequence
            || audit.session_id() != self.session_id
            || now_unix_ms > intent.expires_at_unix_ms
            || preparation.policy_decision.action_hash != intent.action_hash()?
            || self.pending_preparation_hash.as_deref()
                != Some(preparation.prepared.preparation_hash.as_str())
            || self.pending_policy_decision_hash.as_deref()
                != Some(preparation.policy_decision.decision_hash()?.as_str())
        {
            return Err(DesktopError::Replay(
                "commit does not match the pending ordered preparation".to_owned(),
            ));
        }
        if let Some(approval) = approval {
            if self.consumed_approval_ids.contains(&approval.approval_id) {
                return Err(DesktopError::Replay(
                    "approval_id has already been consumed".to_owned(),
                ));
            }
        }
        let permit = match authorize_prepared(
            &self.policy,
            &preparation.policy_decision,
            &preparation.prepared,
            approval,
            now_unix_ms,
        ) {
            Ok(permit) => permit,
            Err(error) => {
                self.audit_terminal_without_commit(
                    audit,
                    AuditEventKind::Denied,
                    intent,
                    &preparation.policy_decision,
                    now_unix_ms,
                    &error.to_string(),
                )?;
                self.consume(intent, approval)?;
                return Err(error);
            }
        };

        audit.append(AuditEvent {
            kind: AuditEventKind::Prepared,
            action_id: intent.action_id.clone(),
            action_sequence: intent.sequence,
            action_hash: preparation.policy_decision.action_hash.clone(),
            policy_decision_hash: preparation.policy_decision.decision_hash()?,
            adapter_descriptor_hash: preparation.policy_decision.adapter_descriptor_hash.clone(),
            preparation_hash: Some(preparation.prepared.preparation_hash.clone()),
            permit_hash: Some(permit.permit_hash().to_owned()),
            approval_id: permit.approval_id().map(str::to_owned),
            output_hash: None,
            message_hash: sha256_bytes(b"prepared and authorized"),
            recorded_at_unix_ms: now_unix_ms,
        })?;

        self.poisoned = true;
        let result =
            self.adapter
                .execute(intent, &preparation.prepared, &permit, payload, now_unix_ms);
        match result {
            Ok(execution) => {
                audit.append(AuditEvent {
                    kind: if execution.outcome.status == ActionOutcomeStatus::Succeeded {
                        AuditEventKind::Succeeded
                    } else {
                        AuditEventKind::Failed
                    },
                    action_id: intent.action_id.clone(),
                    action_sequence: intent.sequence,
                    action_hash: preparation.policy_decision.action_hash.clone(),
                    policy_decision_hash: preparation.policy_decision.decision_hash()?,
                    adapter_descriptor_hash: preparation
                        .policy_decision
                        .adapter_descriptor_hash
                        .clone(),
                    preparation_hash: Some(preparation.prepared.preparation_hash.clone()),
                    permit_hash: Some(permit.permit_hash().to_owned()),
                    approval_id: permit.approval_id().map(str::to_owned),
                    output_hash: Some(execution.outcome.output_hash.clone()),
                    message_hash: sha256_bytes(execution.outcome.message.as_bytes()),
                    recorded_at_unix_ms: now_unix_ms,
                })?;
                self.consume(intent, approval)?;
                self.poisoned = false;
                Ok(execution)
            }
            Err(error) => {
                audit.append(AuditEvent {
                    kind: AuditEventKind::Failed,
                    action_id: intent.action_id.clone(),
                    action_sequence: intent.sequence,
                    action_hash: preparation.policy_decision.action_hash.clone(),
                    policy_decision_hash: preparation.policy_decision.decision_hash()?,
                    adapter_descriptor_hash: preparation
                        .policy_decision
                        .adapter_descriptor_hash
                        .clone(),
                    preparation_hash: Some(preparation.prepared.preparation_hash.clone()),
                    permit_hash: Some(permit.permit_hash().to_owned()),
                    approval_id: permit.approval_id().map(str::to_owned),
                    output_hash: None,
                    message_hash: sha256_bytes(error.to_string().as_bytes()),
                    recorded_at_unix_ms: now_unix_ms,
                })?;
                self.consume(intent, approval)?;
                self.poisoned = false;
                Err(error)
            }
        }
    }

    /// Cancels one pending preparation and consumes its sequence without a side effect.
    pub fn cancel(
        &mut self,
        intent: &DesktopActionIntent,
        preparation: &DesktopActionPreparation,
        now_unix_ms: u64,
        audit: &mut AuditLedger,
    ) -> Result<(), DesktopError> {
        if intent.sequence != self.next_sequence
            || self.pending_preparation_hash.as_deref()
                != Some(preparation.prepared.preparation_hash.as_str())
        {
            return Err(DesktopError::Replay(
                "cancel does not match pending preparation".to_owned(),
            ));
        }
        self.audit_terminal_without_commit(
            audit,
            AuditEventKind::Cancelled,
            intent,
            &preparation.policy_decision,
            now_unix_ms,
            "preparation cancelled before authorization",
        )?;
        self.consume(intent, None)
    }

    /// Convenience path for actions that policy allows without human approval.
    pub fn execute(
        &mut self,
        intent: &DesktopActionIntent,
        decision_envelope: &DecisionEnvelope,
        payload: Option<&[u8]>,
        now_unix_ms: u64,
        audit: &mut AuditLedger,
    ) -> Result<AdapterExecution, DesktopError> {
        let preparation = self.prepare(intent, decision_envelope, now_unix_ms, audit)?;
        self.commit(intent, &preparation, None, payload, now_unix_ms, audit)
    }

    fn validate_session(
        &self,
        intent: &DesktopActionIntent,
        decision_envelope: &DecisionEnvelope,
        now_unix_ms: u64,
        audit: &AuditLedger,
    ) -> Result<(), DesktopError> {
        intent.validate_against_decision(decision_envelope)?;
        if self.poisoned {
            return Err(DesktopError::Integrity(
                "executor is poisoned after an incomplete commit audit".to_owned(),
            ));
        }
        if self.action_count == 0 && audit.record_count() != 0 {
            return Err(DesktopError::Replay(
                "fresh executor cannot attach to a nonempty audit ledger".to_owned(),
            ));
        }
        if intent.session_id != self.session_id || audit.session_id() != self.session_id {
            return Err(DesktopError::Integrity(
                "intent, executor, and audit session identities differ".to_owned(),
            ));
        }
        if intent.sequence != self.next_sequence {
            return Err(DesktopError::Replay(
                "action sequence is duplicated, skipped, or rolled back".to_owned(),
            ));
        }
        if now_unix_ms < intent.generated_at_unix_ms || now_unix_ms > intent.expires_at_unix_ms {
            return Err(DesktopError::AccessDenied(
                "action is not currently valid".to_owned(),
            ));
        }
        if self.action_count >= self.policy.maximum_actions_per_session {
            return Err(DesktopError::AccessDenied(
                "session action budget is exhausted".to_owned(),
            ));
        }
        if self.consumed_action_ids.contains(&intent.action_id) {
            return Err(DesktopError::Replay(
                "action_id has already been consumed".to_owned(),
            ));
        }
        Ok(())
    }

    fn consume(
        &mut self,
        intent: &DesktopActionIntent,
        approval: Option<&HumanApproval>,
    ) -> Result<(), DesktopError> {
        if !self.consumed_action_ids.insert(intent.action_id.clone()) {
            return Err(DesktopError::Replay(
                "action was consumed concurrently".to_owned(),
            ));
        }
        if let Some(approval) = approval {
            if !self
                .consumed_approval_ids
                .insert(approval.approval_id.clone())
            {
                return Err(DesktopError::Replay(
                    "approval was consumed concurrently".to_owned(),
                ));
            }
        }
        self.pending_preparation_hash = None;
        self.pending_policy_decision_hash = None;
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.action_count = self.action_count.saturating_add(1);
        Ok(())
    }

    fn audit_terminal_without_commit(
        &self,
        audit: &mut AuditLedger,
        kind: AuditEventKind,
        intent: &DesktopActionIntent,
        decision: &PolicyDecision,
        now_unix_ms: u64,
        message: &str,
    ) -> Result<(), DesktopError> {
        audit.append(AuditEvent {
            kind,
            action_id: intent.action_id.clone(),
            action_sequence: intent.sequence,
            action_hash: decision.action_hash.clone(),
            policy_decision_hash: decision.decision_hash()?,
            adapter_descriptor_hash: decision.adapter_descriptor_hash.clone(),
            preparation_hash: None,
            permit_hash: None,
            approval_id: None,
            output_hash: None,
            message_hash: sha256_bytes(message.as_bytes()),
            recorded_at_unix_ms: now_unix_ms,
        })?;
        Ok(())
    }
}
