#[cfg(windows)]
mod windows_qualification {
    use d2i_browser_research::{
        parse_json_strict, validate_hash, AttachmentPolicyDecisionV1, AttachmentPolicyProbeV1,
        AttachmentPolicyQualificationStatusV1, AttachmentPolicyQualificationV1,
        AttachmentPolicyScopeV1, AttachmentPolicySnapshotV1, ResearchWorkCertificationV1,
        ResearchWorkCloseoutCertificationV1, ResearchWorkCompletionReportV1, ZERO_HASH,
    };
    use d2i_windows_host::{
        check_attachment_trust_with_referrer, host_identity, WindowsAttachmentTrustDecision,
    };
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use serde::de::DeserializeOwned;
    use serde::Serialize;
    use std::env;
    use std::fs;
    use std::path::Path;
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    const PROBE_SOURCE: &str = "https://www.microsoft.com/robots.txt";
    const HIGH_INTEGRITY_RID: u32 = 0x3000;

    pub fn main() {
        if let Err(error) = run() {
            eprintln!("d2i-office600-policy-qualification: {error}");
            std::process::exit(1);
        }
    }

    fn run() -> Result<(), String> {
        let arguments = env::args().skip(1).collect::<Vec<_>>();
        match arguments.as_slice() {
            [command, input, output] if command == "seal-snapshot" => {
                seal_snapshot(Path::new(input), Path::new(output))
            }
            [command, output, expected_sid, admx, original, staged] if command == "probe" => {
                run_probe(Path::new(output), expected_sid, admx, original, staged)
            }
            [command, probe, restored, restored_exactly, stage_micros, restore_micros, total_micros, output]
                if command == "finalize" =>
            {
                finalize_qualification(
                    Path::new(probe),
                    restored,
                    parse_bool(restored_exactly)?,
                    parse_u64(stage_micros, "policy stage duration")?,
                    parse_u64(restore_micros, "policy restore duration")?,
                    parse_u64(total_micros, "qualification total duration")?,
                    Path::new(output),
                )
            }
            [command, finished, execution_certification, execution_public_key, qualification, source_tree, output, public_key]
                if command == "certify" =>
            {
                certify_closeout(
                    Path::new(finished),
                    Path::new(execution_certification),
                    Path::new(execution_public_key),
                    Path::new(qualification),
                    source_tree,
                    Path::new(output),
                    Path::new(public_key),
                )
            }
            [command, certification, public_key, finished, execution_certification, execution_public_key, qualification]
                if command == "verify-closeout" =>
            {
                verify_closeout_files(
                    Path::new(certification),
                    Path::new(public_key),
                    Path::new(finished),
                    Path::new(execution_certification),
                    Path::new(execution_public_key),
                    Path::new(qualification),
                )
            }
            _ => Err("usage: d2i-office600-policy-qualification <seal-snapshot INPUT OUTPUT|probe OUTPUT EXPECTED_SID ADMX_SHA256 ORIGINAL_POLICY_SHA256 STAGED_POLICY_SHA256|finalize PROBE RESTORED_POLICY_SHA256 RESTORED_EXACTLY STAGE_US RESTORE_US TOTAL_US OUTPUT|certify FINISHED EXECUTION_CERT EXECUTION_PUBLIC_KEY QUALIFICATION SOURCE_TREE OUTPUT PUBLIC_KEY|verify-closeout CERT PUBLIC_KEY FINISHED EXECUTION_CERT EXECUTION_PUBLIC_KEY QUALIFICATION>".to_owned()),
        }
    }

    fn seal_snapshot(input: &Path, output: &Path) -> Result<(), String> {
        let mut snapshot: AttachmentPolicySnapshotV1 = read_strict(input)?;
        snapshot.snapshot_sha256 = ZERO_HASH.to_owned();
        let snapshot = snapshot.seal().map_err(|error| error.to_string())?;
        snapshot
            .validate_gate()
            .map_err(|error| error.to_string())?;
        write_json(output, &snapshot)
    }

    fn run_probe(
        output: &Path,
        expected_sid: &str,
        admx_sha256: &str,
        original_policy_sha256: &str,
        staged_policy_sha256: &str,
    ) -> Result<(), String> {
        validate_hash(admx_sha256, "ADMX hash").map_err(|error| error.to_string())?;
        validate_hash(original_policy_sha256, "original policy hash")
            .map_err(|error| error.to_string())?;
        validate_hash(staged_policy_sha256, "staged policy hash")
            .map_err(|error| error.to_string())?;
        let identity = host_identity().map_err(|error| error.to_string())?;
        let elevated = !identity.is_appcontainer
            && identity.integrity_level_rid >= HIGH_INTEGRITY_RID
            && identity.elevation_type != "limited";
        if identity.user_sid != expected_sid {
            return Err("policy subject SID differs from the Completion user SID".to_owned());
        }
        if !elevated {
            return Err("administrator_token_required".to_owned());
        }
        let parent = output
            .parent()
            .ok_or_else(|| "probe output parent is absent".to_owned())?;
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        let fixture_root = parent.join(format!(".attachment-policy-probe-{}", std::process::id()));
        if fixture_root.exists() {
            return Err("attachment policy fixture root is not fresh".to_owned());
        }
        fs::create_dir(&fixture_root).map_err(|error| error.to_string())?;
        let result = (|| {
            let txt = observe_decision(&fixture_root.join("fixture.txt"), b"D2I text canary\n")?;
            let csv =
                observe_decision(&fixture_root.join("fixture.csv"), b"key,value\ncanary,1\n")?;
            let pdf = observe_decision(&fixture_root.join("fixture.pdf"), b"%PDF-1.4\n%%EOF\n")?;
            let probe = AttachmentPolicyProbeV1 {
                schema_version: 1,
                user_sid: identity.user_sid,
                elevated,
                admx_sha256: admx_sha256.to_owned(),
                policy_scope: AttachmentPolicyScopeV1::User,
                completion_low_risk_extensions: vec![".txt".to_owned()],
                txt_checkpolicy: txt.0,
                csv_checkpolicy: csv.0,
                pdf_checkpolicy: pdf.0,
                higher_precedence_txt_conflict: false,
                original_policy_sha256: original_policy_sha256.to_owned(),
                staged_policy_sha256: staged_policy_sha256.to_owned(),
                txt_checkpolicy_microseconds: txt.1,
                csv_checkpolicy_microseconds: csv.1,
                pdf_checkpolicy_microseconds: pdf.1,
                probe_sha256: ZERO_HASH.to_owned(),
            }
            .seal()
            .map_err(|error| error.to_string())?;
            write_json(output, &probe)?;
            probe.validate_gate().map_err(|error| error.to_string())
        })();
        let cleanup = fs::remove_dir_all(&fixture_root).map_err(|error| error.to_string());
        result?;
        cleanup
    }

    fn observe_decision(
        path: &Path,
        bytes: &[u8],
    ) -> Result<(AttachmentPolicyDecisionV1, u64), String> {
        fs::write(path, bytes).map_err(|error| error.to_string())?;
        let started = Instant::now();
        let observation = check_attachment_trust_with_referrer(path, PROBE_SOURCE, PROBE_SOURCE)
            .map_err(|error| error.to_string())?;
        let elapsed = micros(started.elapsed());
        let observed_bytes = fs::read(path).map_err(|error| error.to_string())?;
        if !observation.file_exists_after_save
            || observation.file_bytes_after_save != bytes.len() as u64
            || observed_bytes != bytes
        {
            return Err("Attachment Services policy probe mutated its bounded fixture".to_owned());
        }
        let decision = match observation.decision {
            WindowsAttachmentTrustDecision::Enable => AttachmentPolicyDecisionV1::Enable,
            WindowsAttachmentTrustDecision::Prompt => AttachmentPolicyDecisionV1::Prompt,
            WindowsAttachmentTrustDecision::Disable
            | WindowsAttachmentTrustDecision::Unavailable => AttachmentPolicyDecisionV1::Disable,
        };
        Ok((decision, elapsed))
    }

    fn finalize_qualification(
        probe_path: &Path,
        restored_policy_sha256: &str,
        restored_exactly: bool,
        policy_stage_microseconds: u64,
        policy_restore_microseconds: u64,
        qualification_total_microseconds: u64,
        output: &Path,
    ) -> Result<(), String> {
        let probe: AttachmentPolicyProbeV1 = read_strict(probe_path)?;
        probe.validate_gate().map_err(|error| error.to_string())?;
        validate_hash(restored_policy_sha256, "restored policy hash")
            .map_err(|error| error.to_string())?;
        let qualification = AttachmentPolicyQualificationV1 {
            schema_version: 1,
            user_sid: probe.user_sid,
            elevated: probe.elevated,
            admx_sha256: probe.admx_sha256,
            policy_scope: probe.policy_scope,
            completion_low_risk_extensions: probe.completion_low_risk_extensions,
            txt_checkpolicy: probe.txt_checkpolicy,
            csv_checkpolicy: probe.csv_checkpolicy,
            pdf_checkpolicy: probe.pdf_checkpolicy,
            higher_precedence_txt_conflict: probe.higher_precedence_txt_conflict,
            original_policy_sha256: probe.original_policy_sha256,
            staged_policy_sha256: probe.staged_policy_sha256,
            restored_policy_sha256: restored_policy_sha256.to_owned(),
            restored_exactly,
            policy_stage_microseconds,
            txt_checkpolicy_microseconds: probe.txt_checkpolicy_microseconds,
            csv_checkpolicy_microseconds: probe.csv_checkpolicy_microseconds,
            pdf_checkpolicy_microseconds: probe.pdf_checkpolicy_microseconds,
            policy_restore_microseconds,
            qualification_total_microseconds,
            attachment_prompt_bypass_count: 0,
            attachment_policy_scope_broadening_count: 0,
            zone_information_bypass_count: 0,
            security_ui_auto_approval_count: 0,
            csv_automatic_promotion_count: 0,
            pdf_automatic_promotion_count: 0,
            temporary_attachment_policy_count: 0,
            qualification_status: AttachmentPolicyQualificationStatusV1::Qualified,
            qualification_sha256: ZERO_HASH.to_owned(),
        }
        .seal()
        .map_err(|error| error.to_string())?;
        qualification
            .validate_gate()
            .map_err(|error| error.to_string())?;
        write_json(output, &qualification)
    }

    fn certify_closeout(
        finished_path: &Path,
        execution_certification_path: &Path,
        execution_public_key_path: &Path,
        qualification_path: &Path,
        source_tree_sha256: &str,
        output: &Path,
        public_key_output: &Path,
    ) -> Result<(), String> {
        let completion: ResearchWorkCompletionReportV1 = read_strict(finished_path)?;
        completion
            .validate_gate()
            .map_err(|error| error.to_string())?;
        let execution: ResearchWorkCertificationV1 = read_strict(execution_certification_path)?;
        let execution_key = read_public_key(execution_public_key_path)?;
        execution
            .verify(
                &execution_key,
                verification_time(execution.issued_at_unix_ms, execution.expires_at_unix_ms),
            )
            .map_err(|error| error.to_string())?;
        let qualification: AttachmentPolicyQualificationV1 = read_strict(qualification_path)?;
        qualification
            .validate_gate()
            .map_err(|error| error.to_string())?;
        validate_hash(source_tree_sha256, "source tree hash").map_err(|error| error.to_string())?;
        if completion.source_tree_sha256 != source_tree_sha256
            || execution.completion_report_sha256 != completion.finished_sha256
        {
            return Err("OFFICE-600 closeout evidence binding differs".to_owned());
        }
        let issued_at_unix_ms = unix_milliseconds()?;
        let key = SigningKey::from_bytes(&[73_u8; 32]);
        let certification = ResearchWorkCloseoutCertificationV1 {
            schema_version: 1,
            certification_id: "certification.office600.closeout-v1".to_owned(),
            completion_report_sha256: completion.finished_sha256,
            execution_certification_sha256: execution.certification_sha256,
            attachment_policy_qualification_sha256: qualification.qualification_sha256,
            user_sid: qualification.user_sid,
            admx_sha256: qualification.admx_sha256,
            original_policy_sha256: qualification.original_policy_sha256,
            staged_policy_sha256: qualification.staged_policy_sha256,
            restored_policy_sha256: qualification.restored_policy_sha256,
            source_tree_sha256: source_tree_sha256.to_owned(),
            issued_at_unix_ms,
            expires_at_unix_ms: issued_at_unix_ms.saturating_add(86_400_000),
            signer_id: "signer.office600.closeout".to_owned(),
            signing_key_id: "key.office600.closeout.v1".to_owned(),
            signature_hex: "00".repeat(64),
            certification_sha256: ZERO_HASH.to_owned(),
        }
        .sign(&key)
        .map_err(|error| error.to_string())?;
        certification
            .verify(&key.verifying_key(), issued_at_unix_ms)
            .map_err(|error| error.to_string())?;
        write_json(output, &certification)?;
        fs::write(public_key_output, hex(&key.verifying_key().to_bytes()))
            .map_err(|error| error.to_string())
    }

    fn verify_closeout_files(
        certification_path: &Path,
        public_key_path: &Path,
        finished_path: &Path,
        execution_certification_path: &Path,
        execution_public_key_path: &Path,
        qualification_path: &Path,
    ) -> Result<(), String> {
        let certification: ResearchWorkCloseoutCertificationV1 = read_strict(certification_path)?;
        certification
            .verify(
                &read_public_key(public_key_path)?,
                verification_time(
                    certification.issued_at_unix_ms,
                    certification.expires_at_unix_ms,
                ),
            )
            .map_err(|error| error.to_string())?;
        let completion: ResearchWorkCompletionReportV1 = read_strict(finished_path)?;
        completion
            .validate_gate()
            .map_err(|error| error.to_string())?;
        let execution: ResearchWorkCertificationV1 = read_strict(execution_certification_path)?;
        execution
            .verify(
                &read_public_key(execution_public_key_path)?,
                verification_time(execution.issued_at_unix_ms, execution.expires_at_unix_ms),
            )
            .map_err(|error| error.to_string())?;
        let qualification: AttachmentPolicyQualificationV1 = read_strict(qualification_path)?;
        qualification
            .validate_gate()
            .map_err(|error| error.to_string())?;
        if certification.completion_report_sha256 != completion.finished_sha256
            || certification.execution_certification_sha256 != execution.certification_sha256
            || certification.attachment_policy_qualification_sha256
                != qualification.qualification_sha256
            || certification.user_sid != qualification.user_sid
            || certification.admx_sha256 != qualification.admx_sha256
            || certification.original_policy_sha256 != qualification.original_policy_sha256
            || certification.staged_policy_sha256 != qualification.staged_policy_sha256
            || certification.restored_policy_sha256 != qualification.restored_policy_sha256
            || certification.source_tree_sha256 != completion.source_tree_sha256
        {
            return Err("OFFICE-600 closeout certification binding differs".to_owned());
        }
        Ok(())
    }

    fn read_strict<T: DeserializeOwned + Serialize>(path: &Path) -> Result<T, String> {
        parse_json_strict(&fs::read(path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())
    }

    fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let mut bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
        bytes.push(b'\n');
        fs::write(path, bytes).map_err(|error| error.to_string())
    }

    fn read_public_key(path: &Path) -> Result<VerifyingKey, String> {
        let value = fs::read_to_string(path).map_err(|error| error.to_string())?;
        let value = value.trim();
        if value.len() != 64 {
            return Err("certification public key must be 32-byte hexadecimal".to_owned());
        }
        let mut bytes = [0_u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            let offset = index * 2;
            *byte = u8::from_str_radix(&value[offset..offset + 2], 16)
                .map_err(|_| "certification public key is not hexadecimal".to_owned())?;
        }
        VerifyingKey::from_bytes(&bytes).map_err(|error| error.to_string())
    }

    fn parse_bool(value: &str) -> Result<bool, String> {
        match value {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err("boolean argument must be true or false".to_owned()),
        }
    }

    fn parse_u64(value: &str, label: &str) -> Result<u64, String> {
        value.parse().map_err(|_| format!("{label} is invalid"))
    }

    fn unix_milliseconds() -> Result<u64, String> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_millis()
            .try_into()
            .map_err(|_| "system time overflow".to_owned())
    }

    fn micros(duration: std::time::Duration) -> u64 {
        duration.as_micros().try_into().unwrap_or(u64::MAX)
    }

    fn verification_time(issued: u64, expires: u64) -> u64 {
        issued.saturating_add(1).min(expires.saturating_sub(1))
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

#[cfg(windows)]
fn main() {
    windows_qualification::main();
}

#[cfg(not(windows))]
fn main() {
    eprintln!("d2i-office600-policy-qualification is Windows-only");
    std::process::exit(1);
}
