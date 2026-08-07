#[path = "support/work_radar_intake_fixture.rs"]
mod work_radar_intake_fixture;

use d2i_desktop::{initialize_case_ledger, persist_new_case, CaseLedgerV1};
use d2i_work_intake::{
    FixtureRadarSourceV1, RadarCheckpointV1, RadarScanRequestV1, RadarSourceAdapterV1,
    RadarSourceApprovalVerificationV1, ZERO_HASH,
};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use work_radar_intake_fixture::{
    activate_governance, digest, evaluate, mapping, new_case, new_case_with_id, ok, registration,
    signal, source_approval, NOW,
};

struct TempTree(PathBuf);

impl TempTree {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(1, |duration| duration.as_nanos());
        let root = std::env::temp_dir().join(format!(
            "d2i-edge100-work-intake-{}-{nonce}",
            std::process::id()
        ));
        ok(std::fs::create_dir_all(&root));
        Self(root)
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn eight_signed_enterprise_observations_create_eight_persistent_cases() {
    let root = TempTree::new();
    let governance = activate_governance(&root.0.join("role"));
    let registration = registration(&governance);
    let approval = source_approval(&governance, &registration);
    let mapping = mapping(&governance, &registration);
    let mut checkpoint = ok(RadarCheckpointV1::initial(
        &registration,
        ZERO_HASH.to_owned(),
        vec!["edge100-initial-source-checkpoint".to_owned()],
    ));
    let mut case_ledger = ok(initialize_case_ledger(
        &root.0.join("cases"),
        "case-ledger-edge100-enterprise-api",
        &registration.organization_id,
        64,
        (NOW - 100) * 1_000,
    ));

    for sequence in 1_u64..=8 {
        let source_signal = signal(
            &registration,
            &format!("enterprise-work-order-event-{sequence}"),
            sequence,
            char::from_digit(sequence as u32, 10)
                .unwrap_or_else(|| panic!("sequence has no fixture digit")),
        );
        let request = ok(RadarScanRequestV1::create(
            format!("edge100-enterprise-cycle-{sequence}"),
            sequence,
            &registration,
            &approval,
            &checkpoint,
            NOW - 1,
            NOW + 10,
        ));
        let mut adapter = ok(FixtureRadarSourceV1::new(vec![source_signal], 1_024, NOW));
        let batch = ok(adapter.scan_once(
            &registration,
            RadarSourceApprovalVerificationV1 {
                source_approval: &approval,
                expected_signer_key_id: "office-source-approval-key-v1",
                verifying_key: &governance.source_approval_key.verifying_key(),
                now_unix_seconds: NOW,
            },
            &checkpoint,
            &request,
        ));
        assert_eq!(
            batch.source_approval_sha256,
            approval.source_approval_sha256
        );
        let observed = batch
            .signals
            .first()
            .unwrap_or_else(|| panic!("enterprise Radar signal is absent"));
        let evaluation = evaluate(
            &governance,
            &registration,
            &approval,
            &mapping,
            &checkpoint,
            observed,
            case_ledger.verification().deduplication_entries.as_slice(),
        );
        assert!(evaluation.requires_case_creation());
        assert!(evaluation.source_envelope.is_some());
        let case = if sequence == 1 {
            new_case(
                &governance,
                &evaluation,
                "case-ledger-edge100-enterprise-api",
            )
        } else {
            new_case_with_id(
                &governance,
                &evaluation,
                "case-ledger-edge100-enterprise-api",
                &format!("case-edge100-enterprise-{sequence}"),
            )
        };
        assert_eq!(case.evidence_index.case_id, case.contract.case_id);
        ok(persist_new_case(
            &mut case_ledger,
            evaluation
                .work_item
                .as_ref()
                .unwrap_or_else(|| panic!("Work Item is absent")),
            evaluation
                .deduplication_key
                .as_ref()
                .unwrap_or_else(|| panic!("deduplication key is absent")),
            evaluation
                .admission
                .as_ref()
                .unwrap_or_else(|| panic!("admission is absent")),
            &case.contract,
            &case.instance,
            &governance.role_ledger_head,
            &digest('8'),
            (NOW + sequence) * 1_000,
        ));
        checkpoint = ok(checkpoint.advance(
            &registration,
            observed,
            sequence,
            digest('9'),
            vec![format!("edge100-cycle-{sequence}-durable")],
        ));
    }

    assert_eq!(case_ledger.verification().current_instances.len(), 8);
    drop(case_ledger);
    let reopened = ok(CaseLedgerV1::open(&root.0.join("cases")));
    assert_eq!(reopened.verification().current_instances.len(), 8);
    assert_eq!(reopened.verification().deduplication_entries.len(), 8);
}
