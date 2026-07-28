use d2i_desktop::{
    activate_certified_windows_binding, attest_windows_wfp_browser_egress, certify_windows_binding,
    create_windows_browser_egress_evidence, create_windows_edge_driver_pin,
    create_windows_wfp_browser_egress_policy, create_windows_wfp_functional_attestation_v2,
    current_windows_host_binding, initialize_windows_activation_ledger,
    initialize_windows_deployment_audit, install_windows_wfp_browser_egress,
    protect_windows_signing_key, remove_windows_wfp_browser_egress, replay_audit,
    run_windows_adapter_worker, run_windows_wfp_browser_egress_self_test,
    run_windows_wfp_verifier_worker, unprotect_windows_signing_key, verify_audit_ledger,
    verify_signed_windows_certification, verify_windows_activation_ledger,
    verify_windows_wfp_browser_egress, verify_windows_wfp_browser_egress_runtime,
    verify_windows_wfp_functional_attestation_v2, AuditReplayExpectation,
    ConcreteWindowsRuntimeBindingProbe, DesktopActionIntent, DesktopError, DesktopPolicy,
    LocalReadOnlyDesktopAdapter, SignedWindowsBrowserEgressEvidence, SignedWindowsCertification,
    SignedWindowsWfpFunctionalAttestationV2, WindowsAdapterConfiguration, WindowsBindingEvidence,
    WindowsBrowserEgressInput, WindowsDeploymentAuditEvent, WindowsDeploymentAuditLedger,
    WindowsEdgeDriverPin, WindowsProtectedSigningKey, WindowsRuntimeBindingProbe,
    WindowsRuntimeManifest, WindowsSigningKeyPurpose, WindowsWfpBrowserEgressPolicy,
    WindowsWfpFunctionalAttestationInputV2,
};
use d2i_desktop::{DesktopAdapter, DesktopAdapterDescriptor};
use ed25519_dalek::SigningKey;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments.as_slice() == ["__windows-worker"] {
        return match run_windows_adapter_worker() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("d2i-desktop worker: {error}");
                ExitCode::from(2)
            }
        };
    }
    if let [mode, browser, verifier_sid, owner_sid, output] = arguments.as_slice() {
        if mode == "__windows-wfp-verifier" {
            return match run_windows_wfp_verifier_worker(
                Path::new(browser),
                verifier_sid,
                owner_sid,
                Path::new(output),
            ) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    let _ = std::fs::write(
                        Path::new(output).with_extension("error.txt"),
                        error.to_string().as_bytes(),
                    );
                    eprintln!("d2i-desktop WFP verifier: {error}");
                    ExitCode::from(2)
                }
            };
        }
    }
    match run(arguments) {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("d2i-desktop: {error}");
            ExitCode::from(2)
        }
    }
}

fn run(arguments: Vec<String>) -> Result<String, DesktopError> {
    match arguments.as_slice() {
        [command, path] if command == "policy-check" => {
            let policy: DesktopPolicy = read_json(Path::new(path))?;
            policy.validate()?;
            Ok(format!("valid policy {}", policy.policy_hash()?))
        }
        [command, path] if command == "intent-check" => {
            let intent: DesktopActionIntent = read_json(Path::new(path))?;
            intent.validate()?;
            Ok(format!("valid action {}", intent.action_hash()?))
        }
        [command, path] if command == "adapter-check" => {
            let descriptor: DesktopAdapterDescriptor = read_json(Path::new(path))?;
            descriptor.validate()?;
            Ok(format!("valid adapter {}", descriptor.descriptor_hash()?))
        }
        [command, path] if command == "windows-config-check" => {
            let configuration: WindowsAdapterConfiguration = read_json(Path::new(path))?;
            configuration.validate()?;
            let output = serde_json::json!({
                "configuration_hash": configuration.configuration_hash()?,
                "adapter_descriptor": configuration.descriptor()?,
            });
            pretty_json(&output)
        }
        [command, path] if command == "windows-manifest-check" => {
            let manifest: WindowsRuntimeManifest = read_json(Path::new(path))?;
            manifest.validate()?;
            Ok(format!("valid Windows manifest {}", manifest.manifest_hash()?))
        }
        [command, root, ledger_id, session_id, maximum_records, created_at]
            if command == "windows-deployment-audit-init" =>
        {
            let _ = initialize_windows_deployment_audit(
                Path::new(root),
                ledger_id,
                session_id,
                parse_u64(maximum_records, "maximum_records")?,
                parse_u64(created_at, "created_at_unix_ms")?,
            )?;
            Ok(format!(
                "initialized Windows deployment audit {ledger_id}"
            ))
        }
        [command, root, event] if command == "windows-deployment-audit-record" => {
            let event: WindowsDeploymentAuditEvent = read_json(Path::new(event))?;
            let mut ledger = WindowsDeploymentAuditLedger::open(Path::new(root))?;
            let record_hash = ledger.append(event)?;
            Ok(format!("appended Windows deployment audit {record_hash}"))
        }
        [command, root] if command == "windows-deployment-audit-check" => {
            pretty_json(&d2i_desktop::verify_windows_deployment_audit(Path::new(
                root,
            ))?)
        }
        [command] if command == "windows-host-binding" => {
            pretty_json(&current_windows_host_binding()?)
        }
        [command, profile_name] if command == "windows-appcontainer-provision" => {
            let profile = d2i_windows_host::provision_appcontainer_profile(profile_name)
                .map_err(|error| {
                    DesktopError::AdapterUnavailable(format!(
                        "AppContainer provisioning failed: {error}"
                    ))
                })?;
            pretty_json(&serde_json::json!({
                "profile_name": profile.profile_name,
                "profile_sid": profile.profile_sid,
                "network_capabilities": []
            }))
        }
        [command, profile_name, worker, browser]
            if command == "windows-wfp-verifier-provision" =>
        {
            let profile = d2i_windows_host::provision_appcontainer_profile(profile_name)
                .map_err(|error| {
                    DesktopError::AdapterUnavailable(format!(
                        "WFP verifier profile provisioning failed: {error}"
                    ))
                })?;
            for path in [worker, browser] {
                d2i_windows_host::grant_appcontainer_path_access(
                    profile_name,
                    Path::new(path),
                    d2i_windows_host::WindowsAppContainerPathAccess::ReadExecute,
                    false,
                )
                .map_err(|error| {
                    DesktopError::Integrity(format!(
                        "WFP verifier read/execute grant failed for {path}: {error}"
                    ))
                })?;
            }
            pretty_json(&serde_json::json!({
                "profile_name": profile.profile_name,
                "profile_sid": profile.profile_sid,
                "network_capabilities": [],
                "wfp_object_access_mask": "0x00020080"
            }))
        }
        [command, profile_name] if command == "windows-appcontainer-delete" => {
            d2i_windows_host::delete_appcontainer_profile(profile_name).map_err(|error| {
                DesktopError::AdapterUnavailable(format!("AppContainer deletion failed: {error}"))
            })?;
            Ok(format!("deleted AppContainer profile {profile_name}"))
        }
        [command, profile_name, access, inherit, path]
            if command == "windows-appcontainer-grant" =>
        {
            let access = match access.as_str() {
                "read_execute" => d2i_windows_host::WindowsAppContainerPathAccess::ReadExecute,
                "read_write" => d2i_windows_host::WindowsAppContainerPathAccess::ReadWrite,
                _ => {
                    return Err(DesktopError::Invalid(
                        "AppContainer path access must be read_execute or read_write".to_owned(),
                    ));
                }
            };
            let inherit = match inherit.as_str() {
                "true" => true,
                "false" => false,
                _ => {
                    return Err(DesktopError::Invalid(
                        "AppContainer grant inherit value must be true or false".to_owned(),
                    ));
                }
            };
            let path = std::fs::canonicalize(path).map_err(|error| DesktopError::Io {
                path: path.clone(),
                message: error.to_string(),
            })?;
            d2i_windows_host::grant_appcontainer_path_access(
                profile_name,
                &path,
                access,
                inherit,
            )
            .map_err(|error| {
                DesktopError::Integrity(format!("AppContainer path grant failed: {error}"))
            })?;
            Ok(format!(
                "granted {access:?} to {profile_name} on {}",
                path.display()
            ))
        }
        [command, raw_key, key_id, purpose, output] if command == "windows-key-protect" => {
            let mut signing_key = read_raw_signing_key(Path::new(raw_key))?;
            let protected =
                protect_windows_signing_key(key_id.clone(), parse_key_purpose(purpose)?, &signing_key)?;
            signing_key = SigningKey::from_bytes(&[0_u8; 32]);
            drop(signing_key);
            write_json_new(Path::new(output), &protected)?;
            d2i_windows_host::harden_path_for_current_user(Path::new(output)).map_err(|error| {
                DesktopError::Integrity(format!(
                    "protected signing key ACL hardening failed: {error}"
                ))
            })?;
            Ok(format!("wrote protected Windows signing key {key_id}"))
        }
        [command, input, protected_key, output] if command == "windows-browser-egress-sign" => {
            let input: WindowsBrowserEgressInput = read_json(Path::new(input))?;
            let signing_key = read_protected_signing_key(
                Path::new(protected_key),
                WindowsSigningKeyPurpose::BrowserEgressProvider,
            )?;
            let evidence = create_windows_browser_egress_evidence(input, &signing_key)?;
            write_json_new(Path::new(output), &evidence)?;
            Ok(format!(
                "wrote signed browser-egress evidence {}",
                evidence.enforcement_id
            ))
        }
        [command, policy] if command == "windows-wfp-egress-install" => {
            let policy: WindowsWfpBrowserEgressPolicy = read_json(Path::new(policy))?;
            pretty_json(&install_windows_wfp_browser_egress(&policy)?)
        }
        [command, enforcement_id, browser, verifier_profile, output]
            if command == "windows-wfp-egress-policy" =>
        {
            let policy = create_windows_wfp_browser_egress_policy(
                enforcement_id.clone(),
                Path::new(browser),
                verifier_profile,
            )?;
            write_json_new(Path::new(output), &policy)?;
            Ok(format!("wrote WFP browser-egress policy {enforcement_id}"))
        }
        [command, policy] if command == "windows-wfp-egress-check" => {
            let policy: WindowsWfpBrowserEgressPolicy = read_json(Path::new(policy))?;
            pretty_json(&verify_windows_wfp_browser_egress(&policy)?)
        }
        [command, configuration] if command == "windows-wfp-egress-runtime-check" => {
            let configuration: WindowsAdapterConfiguration =
                read_json(Path::new(configuration))?;
            pretty_json(&verify_windows_wfp_browser_egress_runtime(&configuration)?)
        }
        [command, attestation, provider_public_key, now]
            if command == "windows-wfp-egress-attestation-check" =>
        {
            let attestation: SignedWindowsWfpFunctionalAttestationV2 =
                read_json(Path::new(attestation))?;
            verify_windows_wfp_functional_attestation_v2(
                &attestation,
                provider_public_key,
                parse_u64(now, "now_unix_seconds")?,
            )?;
            pretty_json(&serde_json::json!({
                "attestation_hash": attestation.attestation_hash()?,
                "self_test_report_hash": attestation.self_test_report_hash,
                "activation_challenge": attestation.activation_challenge,
                "issued_at_unix_seconds": attestation.issued_at_unix_seconds,
                "expires_at_unix_seconds": attestation.expires_at_unix_seconds,
                "browser_version": attestation.browser_version,
                "browser_executable_hash": attestation.browser_executable_hash,
                "driver_version": attestation.driver_version,
                "driver_executable_hash": attestation.driver_executable_hash,
            }))
        }
        [command, policy, pin, activation_challenge, blocked_observation_ms, output]
            if command == "windows-wfp-egress-self-test" =>
        {
            let policy: WindowsWfpBrowserEgressPolicy = read_json(Path::new(policy))?;
            let pin: WindowsEdgeDriverPin = read_json(Path::new(pin))?;
            let report = run_windows_wfp_browser_egress_self_test(
                &policy,
                &pin,
                activation_challenge,
                parse_u64(blocked_observation_ms, "blocked observation milliseconds")?,
            )?;
            let report_hash = report.report_hash()?;
            write_json_new(Path::new(output), &report)?;
            if !report.passed {
                return Err(DesktopError::Integrity(format!(
                    "WFP browser-egress functional self-test failed; report {report_hash}"
                )));
            }
            Ok(format!(
                "passed WFP browser-egress functional self-test {report_hash}"
            ))
        }
        [command, policy] if command == "windows-wfp-egress-remove" => {
            let policy: WindowsWfpBrowserEgressPolicy = read_json(Path::new(policy))?;
            remove_windows_wfp_browser_egress(&policy)?;
            Ok("removed Windows WFP browser-egress policy".to_owned())
        }
        [command, policy, input, protected_key, output]
            if command == "windows-wfp-egress-attest" =>
        {
            let policy: WindowsWfpBrowserEgressPolicy = read_json(Path::new(policy))?;
            let input: WindowsBrowserEgressInput = read_json(Path::new(input))?;
            let signing_key = read_protected_signing_key(
                Path::new(protected_key),
                WindowsSigningKeyPurpose::BrowserEgressProvider,
            )?;
            let evidence =
                attest_windows_wfp_browser_egress(&policy, input, &signing_key)?;
            write_json_new(Path::new(output), &evidence)?;
            Ok(format!(
                "wrote WFP-verified browser-egress evidence {}",
                evidence.enforcement_id
            ))
        }
        [
            command,
            policy,
            pin,
            input,
            protected_key,
            activation_challenge,
            blocked_observation_ms,
            report_output,
            evidence_output,
        ] if command == "windows-wfp-egress-functional-attest" => {
            let policy: WindowsWfpBrowserEgressPolicy = read_json(Path::new(policy))?;
            let pin: WindowsEdgeDriverPin = read_json(Path::new(pin))?;
            let input: WindowsWfpFunctionalAttestationInputV2 =
                read_json(Path::new(input))?;
            if input.activation_challenge != *activation_challenge {
                return Err(DesktopError::Replay(
                    "CLI activation challenge differs from attestation input".to_owned(),
                ));
            }
            let report = run_windows_wfp_browser_egress_self_test(
                &policy,
                &pin,
                activation_challenge,
                parse_u64(blocked_observation_ms, "blocked observation milliseconds")?,
            )?;
            let report_hash = report.report_hash()?;
            write_json_new(Path::new(report_output), &report)?;
            if !report.passed {
                return Err(DesktopError::Integrity(format!(
                    "WFP browser-egress functional self-test failed; report {report_hash}"
                )));
            }
            let protected: WindowsProtectedSigningKey =
                read_json(Path::new(protected_key))?;
            if input.signer_key_id != protected.key_id {
                return Err(DesktopError::Integrity(
                    "attestation signer key ID differs from the protected key".to_owned(),
                ));
            }
            let signing_key = unprotect_windows_signing_key(
                &protected,
                WindowsSigningKeyPurpose::BrowserEgressProvider,
            )?;
            let evidence = create_windows_wfp_functional_attestation_v2(
                &policy,
                &pin,
                &report,
                input,
                &signing_key,
            )?;
            write_json_new(Path::new(evidence_output), &evidence)?;
            Ok(format!(
                "wrote functionally tested WFP browser-egress evidence {} with report {report_hash}",
                evidence.enforcement_id
            ))
        }
        [command, browser, driver, output] if command == "windows-edgedriver-pin" => {
            let pin = create_windows_edge_driver_pin(Path::new(browser), Path::new(driver))?;
            write_json_new(Path::new(output), &pin)?;
            Ok(format!(
                "wrote EdgeDriver pin {}",
                pin.compatibility_version
            ))
        }
        [command, path] if command == "windows-edgedriver-check" => {
            let pin: WindowsEdgeDriverPin = read_json(Path::new(path))?;
            pin.verify()?;
            Ok(format!(
                "valid EdgeDriver pin {}",
                pin.compatibility_version
            ))
        }
        [
            command,
            configuration,
            binding_id,
            integration_id,
            observed,
            expires,
            attestor_id,
            attestor_key,
            evidence_output,
        ] if command == "windows-probe" => {
            let configuration: WindowsAdapterConfiguration =
                read_json(Path::new(configuration))?;
            let signing_key = read_protected_signing_key(
                Path::new(attestor_key),
                WindowsSigningKeyPurpose::BindingAttestor,
            )?;
            let probe = ConcreteWindowsRuntimeBindingProbe::new(
                configuration,
                binding_id.clone(),
                integration_id.clone(),
                parse_u64(observed, "observed_at_unix_seconds")?,
                parse_u64(expires, "expires_at_unix_seconds")?,
                attestor_id.clone(),
                signing_key,
            )?;
            let evidence = probe.collect_binding_evidence()?;
            write_json_new(Path::new(evidence_output), &evidence)?;
            Ok(format!("wrote signed Windows evidence {}", evidence.binding_id))
        }
        [
            command,
            configuration,
            binding_id,
            integration_id,
            observed,
            expires,
            attestor_id,
            attestor_key,
            browser_egress,
            evidence_output,
        ] if command == "windows-probe" => {
            let configuration: WindowsAdapterConfiguration =
                read_json(Path::new(configuration))?;
            let signing_key = read_protected_signing_key(
                Path::new(attestor_key),
                WindowsSigningKeyPurpose::BindingAttestor,
            )?;
            let probe = ConcreteWindowsRuntimeBindingProbe::new(
                configuration,
                binding_id.clone(),
                integration_id.clone(),
                parse_u64(observed, "observed_at_unix_seconds")?,
                parse_u64(expires, "expires_at_unix_seconds")?,
                attestor_id.clone(),
                signing_key,
            )?;
            let probe = if probe.configuration.browser_egress_policy.is_some() {
                let attestation: SignedWindowsWfpFunctionalAttestationV2 =
                    read_json(Path::new(browser_egress))?;
                probe.with_wfp_functional_attestation(attestation)?
            } else {
                let evidence: SignedWindowsBrowserEgressEvidence =
                    read_json(Path::new(browser_egress))?;
                probe.with_browser_egress_evidence(evidence)?
            };
            let evidence = probe.collect_binding_evidence()?;
            write_json_new(Path::new(evidence_output), &evidence)?;
            Ok(format!("wrote signed Windows evidence {}", evidence.binding_id))
        }
        [
            command,
            manifest,
            evidence,
            certification_id,
            certifier_id,
            certifier_key,
            now,
            report_output,
            certification_output,
        ] if command == "windows-certify" => {
            let manifest: WindowsRuntimeManifest = read_json(Path::new(manifest))?;
            let evidence: WindowsBindingEvidence = read_json(Path::new(evidence))?;
            let signing_key = read_protected_signing_key(
                Path::new(certifier_key),
                WindowsSigningKeyPurpose::Certifier,
            )?;
            let result = certify_windows_binding(
                &manifest,
                &evidence,
                certification_id.clone(),
                certifier_id.clone(),
                &signing_key,
                parse_u64(now, "now_unix_seconds")?,
            )?;
            write_json_new(Path::new(report_output), &result.report)?;
            let certification = result.signed_certification.ok_or_else(|| {
                DesktopError::Integrity(
                    "Windows certification failed; inspect the written report".to_owned(),
                )
            })?;
            write_json_new(Path::new(certification_output), &certification)?;
            Ok(format!(
                "wrote signed Windows certification {}",
                certification.certification_id
            ))
        }
        [command, manifest, evidence, certification, now]
            if command == "windows-certification-check" =>
        {
            let manifest: WindowsRuntimeManifest = read_json(Path::new(manifest))?;
            let evidence: WindowsBindingEvidence = read_json(Path::new(evidence))?;
            let certification: SignedWindowsCertification =
                read_json(Path::new(certification))?;
            let _ = verify_signed_windows_certification(
                &manifest,
                &evidence,
                &certification,
                parse_u64(now, "now_unix_seconds")?,
            )?;
            Ok(format!(
                "valid Windows certification {}",
                certification.certification_id
            ))
        }
        [command, root, ledger_id, manifest, activator_id, maximum_entries]
            if command == "windows-activation-init" =>
        {
            let manifest: WindowsRuntimeManifest = read_json(Path::new(manifest))?;
            let verification = initialize_windows_activation_ledger(
                Path::new(root),
                ledger_id,
                &manifest,
                BTreeSet::from([activator_id.clone()]),
                parse_u64(maximum_entries, "maximum_entries")?,
            )?;
            pretty_json(&verification)
        }
        [command, root] if command == "windows-activation-check" => {
            pretty_json(&verify_windows_activation_ledger(Path::new(root))?)
        }
        [command, root, activator_id, manifest, evidence, certification, now]
            if command == "windows-activate" =>
        {
            let manifest: WindowsRuntimeManifest = read_json(Path::new(manifest))?;
            let evidence: WindowsBindingEvidence = read_json(Path::new(evidence))?;
            let certification: SignedWindowsCertification =
                read_json(Path::new(certification))?;
            let now = parse_u64(now, "now_unix_seconds")?;
            let certified =
                verify_signed_windows_certification(&manifest, &evidence, &certification, now)?;
            let admission =
                activate_certified_windows_binding(Path::new(root), activator_id, certified, now)?;
            pretty_json(&admission.verification)
        }
        [command, path] if command == "audit-check" => {
            let report = verify_audit_ledger(Path::new(path))?;
            serde_json::to_string_pretty(&report)
                .map_err(|error| DesktopError::Json(error.to_string()))
        }
        [command, ledger, expectation] if command == "audit-replay" => {
            let expectation: AuditReplayExpectation = read_json(Path::new(expectation))?;
            let report = replay_audit(Path::new(ledger), &expectation)?;
            let output = serde_json::to_string_pretty(&report)
                .map_err(|error| DesktopError::Json(error.to_string()))?;
            if !report.matched {
                return Err(DesktopError::Replay(output));
            }
            Ok(output)
        }
        [command, roots @ ..] if command == "local-readonly-descriptor" && !roots.is_empty() => {
            let paths: Vec<PathBuf> = roots.iter().map(PathBuf::from).collect();
            let adapter = LocalReadOnlyDesktopAdapter::new(&paths)?;
            serde_json::to_string_pretty(adapter.descriptor())
                .map_err(|error| DesktopError::Json(error.to_string()))
        }
        _ => Err(DesktopError::Invalid(
            "usage: d2i-desktop <policy-check|intent-check|adapter-check|audit-check|windows-config-check|windows-manifest-check|windows-activation-check|windows-edgedriver-check|windows-wfp-egress-install|windows-wfp-egress-check|windows-wfp-egress-remove> <path> | windows-wfp-egress-policy <enforcement-id> <browser> <verifier-profile> <output> | windows-wfp-egress-self-test <policy> <edge-pin> <activation-challenge> <blocked-observation-ms> <report-output> | windows-edgedriver-pin <browser> <driver> <output> | windows-wfp-egress-attest <policy> <input> <protected-key> <output> | windows-wfp-egress-functional-attest <policy> <edge-pin> <input> <protected-key> <activation-challenge> <blocked-observation-ms> <report-output> <evidence-output> | audit-replay <ledger> <expectation> | local-readonly-descriptor <root>... | windows-appcontainer-provision <name> | windows-appcontainer-grant <name> <read_execute|read_write> <true|false> <path> | windows-appcontainer-delete <name> | windows-key-protect <raw-key> <key-id> <purpose> <output> | windows-browser-egress-sign <input> <protected-key> <output> | windows-probe <config> <binding-id> <integration-id> <observed> <expires> <attestor-id> <protected-key> [browser-egress] <evidence-output> | windows-certify <manifest> <evidence> <certification-id> <certifier-id> <protected-key> <now> <report-output> <certification-output> | windows-certification-check <manifest> <evidence> <certification> <now> | windows-activation-init <root> <ledger-id> <manifest> <activator-id> <maximum-entries> | windows-activate <root> <activator-id> <manifest> <evidence> <certification> <now>".to_owned(),
        )),
    }
}

fn parse_u64(value: &str, field: &str) -> Result<u64, DesktopError> {
    value
        .parse::<u64>()
        .map_err(|_| DesktopError::Invalid(format!("{field} must be an unsigned integer")))
}

fn pretty_json<T: Serialize>(value: &T) -> Result<String, DesktopError> {
    serde_json::to_string_pretty(value).map_err(|error| DesktopError::Json(error.to_string()))
}

fn read_raw_signing_key(path: &Path) -> Result<SigningKey, DesktopError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| DesktopError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 256 {
        return Err(DesktopError::Integrity(
            "signing key must be a bounded non-symlink regular file".to_owned(),
        ));
    }
    let value = std::fs::read_to_string(path).map_err(|error| DesktopError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })?;
    let value = value.trim();
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(DesktopError::Invalid(
            "signing key must contain exactly 32 bytes encoded as hex".to_owned(),
        ));
    }
    let mut bytes = [0_u8; 32];
    for (index, slot) in bytes.iter_mut().enumerate() {
        let offset = index * 2;
        *slot = u8::from_str_radix(&value[offset..offset + 2], 16)
            .map_err(|error| DesktopError::Invalid(error.to_string()))?;
    }
    let key = SigningKey::from_bytes(&bytes);
    bytes.fill(0);
    Ok(key)
}

fn read_protected_signing_key(
    path: &Path,
    purpose: WindowsSigningKeyPurpose,
) -> Result<SigningKey, DesktopError> {
    let protected: WindowsProtectedSigningKey = read_json(path)?;
    unprotect_windows_signing_key(&protected, purpose)
}

fn parse_key_purpose(value: &str) -> Result<WindowsSigningKeyPurpose, DesktopError> {
    match value {
        "binding_attestor" => Ok(WindowsSigningKeyPurpose::BindingAttestor),
        "certifier" => Ok(WindowsSigningKeyPurpose::Certifier),
        "browser_egress_provider" => Ok(WindowsSigningKeyPurpose::BrowserEgressProvider),
        _ => Err(DesktopError::Invalid(
            "key purpose must be binding_attestor, certifier, or browser_egress_provider"
                .to_owned(),
        )),
    }
}

fn write_json_new<T: Serialize>(path: &Path, value: &T) -> Result<(), DesktopError> {
    let mut bytes =
        serde_json::to_vec_pretty(value).map_err(|error| DesktopError::Json(error.to_string()))?;
    bytes.push(b'\n');
    if bytes.len() > 2 * 1024 * 1024 {
        return Err(DesktopError::Invalid(
            "CLI output exceeds the JSON artifact bound".to_owned(),
        ));
    }
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| DesktopError::Io {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| DesktopError::Io {
            path: path.display().to_string(),
            message: error.to_string(),
        })
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, DesktopError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| DesktopError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 2 * 1024 * 1024
    {
        return Err(DesktopError::Integrity(
            "CLI input must be a bounded non-symlink regular file".to_owned(),
        ));
    }
    let bytes = std::fs::read(path).map_err(|error| DesktopError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })?;
    serde_json::from_slice(&bytes).map_err(|error| DesktopError::Json(error.to_string()))
}
