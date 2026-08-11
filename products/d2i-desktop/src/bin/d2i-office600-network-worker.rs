#[cfg(windows)]
mod windows_worker {
    use d2i_browser_research::{
        admit_research_url_v1, resolve_public_addresses_v1, resolve_redirect_location_v1,
        semantic_download_filename_v1, sha256_bytes, validate_controlled_download_intent_v1,
        validate_controlled_download_request_v1, validate_network_profile_v1,
        validate_research_fetch_request_v1, validate_source_policy_v1,
        verify_connected_remote_address_v1, ControlledDownloadIntentV1,
        ControlledDownloadReceiptV1, ControlledDownloadRequestV1, FetchResultCodeV1,
        ResearchFetchReceiptV1, ResearchFetchRequestV1, ResearchHttpMetadataV1,
        ResearchHttpMethodV1, ResearchNetworkProfileV1, ResearchNetworkWorkerAuthorizationV1,
        ResearchNetworkWorkerOperationV1, ResearchSourcePolicyV1, ResearchUrlAdmissionDecisionV1,
        ResearchUrlAdmissionRequestV1, SourcePolicyClassV1, UrlAdmissionOutcomeV1, ZERO_HASH,
    };
    use d2i_windows_host::{
        process_peak_working_set_bytes, winhttp_research_request, WindowsResearchHttpMethod,
        WindowsWinHttpRequest,
    };
    use ed25519_dalek::VerifyingKey;
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeSet;
    use std::env;
    use std::fs::{self, OpenOptions};
    use std::io::{self, Read, Write};
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};
    use url::Url;

    const MAX_PRIVATE_INPUT_BYTES: u64 = 2 * 1024 * 1024;

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct NetworkWorkerInputV1 {
        schema_version: u32,
        action: String,
        raw_url: String,
        admission_request: ResearchUrlAdmissionRequestV1,
        fetch_request: Option<ResearchFetchRequestV1>,
        download_request: Option<ControlledDownloadRequestV1>,
        download_intent: Option<ControlledDownloadIntentV1>,
        authorization: ResearchNetworkWorkerAuthorizationV1,
        network_profile: ResearchNetworkProfileV1,
        source_policy: ResearchSourcePolicyV1,
        verifying_key_hex: String,
    }

    #[derive(Debug, Serialize)]
    #[serde(deny_unknown_fields)]
    struct NetworkWorkerOutputV1 {
        schema_version: u32,
        fetch_receipt: Option<ResearchFetchReceiptV1>,
        download_receipt: Option<ControlledDownloadReceiptV1>,
        admission_decisions: Vec<ResearchUrlAdmissionDecisionV1>,
        final_url_protected_ref: String,
        final_source_class: SourcePolicyClassV1,
        connected_remote_address: Option<String>,
        body_file_name: Option<String>,
        worker_executable_sha256: String,
        url_admission_microseconds: u64,
        dns_microseconds: u64,
        connect_microseconds: u64,
        tls_microseconds: u64,
        ttfb_microseconds: u64,
        transfer_microseconds: u64,
        peak_worker_memory_bytes: u64,
        complete: bool,
    }

    struct FreshAdmission {
        outcome: UrlAdmissionOutcomeV1,
        url_admission_microseconds: u64,
        dns_microseconds: u64,
    }

    struct ActionBinding<'a> {
        operation: ResearchNetworkWorkerOperationV1,
        method: ResearchHttpMethodV1,
        request_sha256: &'a str,
        maximum_response_bytes: u64,
    }

    pub fn main() {
        if let Err(error) = run() {
            eprintln!("OFFICE-600 network worker failed: {error}");
            std::process::exit(1);
        }
    }

    fn run() -> Result<(), String> {
        let current_directory = prepare_empty_output_directory()?;
        let input = read_private_input()?;
        validate_network_profile_v1(&input.network_profile).map_err(|error| error.to_string())?;
        validate_source_policy_v1(&input.source_policy).map_err(|error| error.to_string())?;
        let executable_sha256 = current_executable_sha256()?;
        let now = unix_milliseconds()?;
        let binding = validate_action(&input, now, &executable_sha256)?;
        let verifying_key = decode_verifying_key(&input.verifying_key_hex)?;
        input
            .authorization
            .verify(&verifying_key, now, &executable_sha256)
            .map_err(|error| error.to_string())?;
        if input.authorization.organization_id != input.admission_request.organization_id
            || input.authorization.case_id != input.admission_request.case_id
            || input.authorization.request_sha256 != binding.request_sha256
            || input.authorization.operation != binding.operation
            || input.authorization.method != binding.method
            || input.authorization.maximum_response_bytes != binding.maximum_response_bytes
        {
            return Err("network worker authorization binding differs".to_owned());
        }
        if binding.operation == ResearchNetworkWorkerOperationV1::AdmitUrl {
            let admission = admit_with_fresh_dns(
                &input.admission_request,
                &input.raw_url,
                &input.network_profile,
                &input.source_policy,
            )?;
            let admitted = admission
                .outcome
                .admitted
                .ok_or_else(|| "URL admission did not produce a network target".to_owned())?;
            let output = NetworkWorkerOutputV1 {
                schema_version: 1,
                fetch_receipt: None,
                download_receipt: None,
                admission_decisions: vec![admission.outcome.decision],
                final_url_protected_ref: admitted.protected_ref().to_owned(),
                final_source_class: admitted.source_class(),
                connected_remote_address: None,
                body_file_name: None,
                worker_executable_sha256: executable_sha256,
                url_admission_microseconds: admission.url_admission_microseconds,
                dns_microseconds: admission.dns_microseconds,
                connect_microseconds: 0,
                tls_microseconds: 0,
                ttfb_microseconds: 0,
                transfer_microseconds: 0,
                peak_worker_memory_bytes: process_peak_working_set_bytes(std::process::id())
                    .map_err(|error| error.to_string())?,
                complete: true,
            };
            println!(
                "{}",
                serde_json::to_string(&output).map_err(|error| error.to_string())?
            );
            return Ok(());
        }
        let mut current_url = input.raw_url.clone();
        let mut admission_request = input.admission_request.clone();
        let mut decisions = Vec::new();
        let mut redirect_hashes = Vec::new();
        let mut visited_url_hashes = BTreeSet::new();
        let mut url_admission_microseconds = 0_u64;
        let mut dns_microseconds = 0_u64;
        let mut connect_microseconds = 0_u64;
        let mut tls_microseconds = 0_u64;
        let mut ttfb_microseconds = 0_u64;
        let mut transfer_microseconds = 0_u64;
        let started = std::time::Instant::now();
        let final_state = loop {
            if !visited_url_hashes.insert(sha256_bytes(current_url.as_bytes())) {
                return Err("redirect loop rejected".to_owned());
            }
            let admission = admit_with_fresh_dns(
                &admission_request,
                &current_url,
                &input.network_profile,
                &input.source_policy,
            )?;
            url_admission_microseconds =
                url_admission_microseconds.saturating_add(admission.url_admission_microseconds);
            dns_microseconds = dns_microseconds.saturating_add(admission.dns_microseconds);
            if decisions.is_empty() {
                let expected = match (&input.fetch_request, &input.download_request) {
                    (Some(request), None) => &request.url_admission_decision_sha256,
                    (None, Some(request)) => &request.url_admission_decision_sha256,
                    _ => return Err("network worker request shape differs".to_owned()),
                };
                if &admission.outcome.decision.decision_sha256 != expected {
                    return Err("fresh URL admission differs from signed request".to_owned());
                }
            } else {
                redirect_hashes.push(admission.outcome.decision.decision_sha256.clone());
            }
            let admitted = admission
                .outcome
                .admitted
                .ok_or_else(|| "URL admission did not produce a network target".to_owned())?;
            decisions.push(admission.outcome.decision);
            let response = winhttp_research_request(WindowsWinHttpRequest {
                host: admitted.host(),
                path_and_query: &admitted.path_and_query(),
                method: match binding.method {
                    ResearchHttpMethodV1::Get => WindowsResearchHttpMethod::Get,
                    ResearchHttpMethodV1::Head => WindowsResearchHttpMethod::Head,
                },
                connect_timeout_milliseconds: input.network_profile.connect_timeout_milliseconds,
                receive_timeout_milliseconds: input.network_profile.receive_timeout_milliseconds,
                maximum_header_bytes: input.network_profile.max_response_headers,
                maximum_response_bytes: binding.maximum_response_bytes,
            })
            .map_err(|error| error.to_string())?;
            connect_microseconds =
                connect_microseconds.saturating_add(response.connect_microseconds);
            tls_microseconds = tls_microseconds.saturating_add(response.tls_microseconds);
            ttfb_microseconds = ttfb_microseconds.saturating_add(response.ttfb_microseconds);
            transfer_microseconds =
                transfer_microseconds.saturating_add(response.transfer_microseconds);
            verify_connected_remote_address_v1(&admitted, response.remote_address)
                .map_err(|error| error.to_string())?;
            if (300..400).contains(&response.status_code) {
                let location = response
                    .location
                    .as_deref()
                    .ok_or_else(|| "redirect response omitted Location".to_owned())?;
                current_url = resolve_redirect_location_v1(
                    &admitted,
                    location,
                    u32::try_from(redirect_hashes.len()).map_err(|_| "redirect count overflow")?,
                    &input.network_profile,
                )
                .map_err(|error| error.to_string())?;
                admission_request = redirected_admission_request(
                    &input.admission_request,
                    &current_url,
                    decisions.len(),
                )?;
                continue;
            }
            break (admitted, response);
        };
        let (admitted, response) = final_state;
        let result = classify_status(response.status_code);
        let body_sha256 = sha256_bytes(&response.body);
        let metadata = ResearchHttpMetadataV1 {
            status_code: response.status_code,
            content_type: response.content_type.clone(),
            declared_content_length: response.declared_content_length,
            total_header_bytes: response.total_header_bytes,
            content_encoding: response.content_encoding.clone(),
            certificate_thumbprint_sha256: response.certificate_sha256,
            remote_address_sha256: sha256_bytes(response.remote_address.to_string().as_bytes()),
            metadata_sha256: ZERO_HASH.to_owned(),
        }
        .seal()
        .map_err(|error| error.to_string())?;
        let request_sha256 = binding.request_sha256.to_owned();
        let fetch_receipt = ResearchFetchReceiptV1 {
            schema_version: 1,
            receipt_id: format!(
                "fetch-receipt:{}",
                input.admission_request.source_candidate_id
            ),
            request_sha256,
            http_metadata: metadata,
            bytes_received: response.body.len() as u64,
            body_sha256: body_sha256.clone(),
            redirect_chain_sha256: redirect_hashes,
            elapsed_microseconds: u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
            result,
            receipt_sha256: ZERO_HASH.to_owned(),
        }
        .seal()
        .map_err(|error| error.to_string())?;
        let successful = result == FetchResultCodeV1::Success;
        let body_file_name = if successful && !response.body.is_empty() {
            Some(write_body(
                &current_directory,
                output_filename(&input)?,
                &response.body,
            )?)
        } else {
            None
        };
        let download_receipt = match (&input.download_request, &input.download_intent) {
            (Some(request), Some(_intent)) if successful => Some(
                ControlledDownloadReceiptV1 {
                    schema_version: 1,
                    receipt_id: format!("download-receipt:{}", request.quarantine_artifact_id),
                    request_sha256: request.request_sha256.clone(),
                    fetch_receipt_sha256: fetch_receipt.receipt_sha256.clone(),
                    quarantine_artifact_id: request.quarantine_artifact_id.clone(),
                    untrusted_filename_sha256: sha256_bytes(
                        response
                            .content_disposition
                            .as_deref()
                            .unwrap_or("")
                            .as_bytes(),
                    ),
                    sanitized_filename: body_file_name.clone().ok_or_else(|| {
                        "successful controlled download did not create a body file".to_owned()
                    })?,
                    bytes_received: response.body.len() as u64,
                    pre_trust_sha256: body_sha256,
                    receipt_sha256: ZERO_HASH.to_owned(),
                }
                .seal()
                .map_err(|error| error.to_string())?,
            ),
            (None, None) => None,
            (Some(_), Some(_)) => None,
            _ => return Err("download request and intent must appear together".to_owned()),
        };
        let output = NetworkWorkerOutputV1 {
            schema_version: 1,
            fetch_receipt: Some(fetch_receipt),
            download_receipt,
            admission_decisions: decisions,
            final_url_protected_ref: admitted.protected_ref().to_owned(),
            final_source_class: admitted.source_class(),
            connected_remote_address: Some(response.remote_address.to_string()),
            body_file_name,
            worker_executable_sha256: executable_sha256,
            url_admission_microseconds,
            dns_microseconds,
            connect_microseconds,
            tls_microseconds,
            ttfb_microseconds,
            transfer_microseconds,
            peak_worker_memory_bytes: process_peak_working_set_bytes(std::process::id())
                .map_err(|error| error.to_string())?,
            complete: successful,
        };
        let json = serde_json::to_string(&output).map_err(|error| error.to_string())?;
        println!("{json}");
        Ok(())
    }

    fn validate_action<'a>(
        input: &'a NetworkWorkerInputV1,
        now: u64,
        executable_sha256: &str,
    ) -> Result<ActionBinding<'a>, String> {
        if input.schema_version != 1
            || input.admission_request.organization_id != input.source_policy.organization_id
            || input.admission_request.network_profile_sha256
                != input.network_profile.network_profile_sha256
            || input.admission_request.source_policy_sha256 != input.source_policy.policy_sha256
        {
            return Err("network worker input bindings differ".to_owned());
        }
        match (
            input.action.as_str(),
            &input.fetch_request,
            &input.download_request,
            &input.download_intent,
        ) {
            ("admit", None, None, None) => {
                input
                    .admission_request
                    .validate_seal()
                    .map_err(|error| error.to_string())?;
                Ok(ActionBinding {
                    operation: ResearchNetworkWorkerOperationV1::AdmitUrl,
                    method: ResearchHttpMethodV1::Head,
                    request_sha256: &input.admission_request.request_sha256,
                    maximum_response_bytes: 1,
                })
            }
            ("fetch", Some(request), None, None) => {
                validate_research_fetch_request_v1(
                    request,
                    &input.network_profile,
                    now,
                    executable_sha256,
                )
                .map_err(|error| error.to_string())?;
                Ok(ActionBinding {
                    operation: ResearchNetworkWorkerOperationV1::FetchPage,
                    method: request.method,
                    request_sha256: &request.request_sha256,
                    maximum_response_bytes: input.network_profile.max_response_bytes,
                })
            }
            ("download", None, Some(request), Some(intent)) => {
                validate_controlled_download_intent_v1(intent, &input.source_policy, true)
                    .map_err(|error| error.to_string())?;
                validate_controlled_download_request_v1(
                    request,
                    intent,
                    &input.network_profile,
                    now,
                    executable_sha256,
                )
                .map_err(|error| error.to_string())?;
                Ok(ActionBinding {
                    operation: ResearchNetworkWorkerOperationV1::DownloadArtifact,
                    method: ResearchHttpMethodV1::Get,
                    request_sha256: &request.request_sha256,
                    maximum_response_bytes: intent.maximum_bytes,
                })
            }
            _ => Err("network worker accepts exactly one fetch or download".to_owned()),
        }
    }

    fn admit_with_fresh_dns(
        request: &ResearchUrlAdmissionRequestV1,
        raw_url: &str,
        profile: &ResearchNetworkProfileV1,
        policy: &ResearchSourcePolicyV1,
    ) -> Result<FreshAdmission, String> {
        let admission_started = std::time::Instant::now();
        let preflight = admit_research_url_v1(request, raw_url, &[], profile, policy)
            .map_err(|error| error.to_string())?;
        if preflight.decision.reason_code != "dns_resolution_empty" {
            return Err(format!(
                "URL preflight rejected: {}",
                preflight.decision.reason_code
            ));
        }
        let parsed = Url::parse(raw_url).map_err(|_| "URL cannot be parsed".to_owned())?;
        let host = parsed
            .host_str()
            .ok_or_else(|| "URL hostname is absent".to_owned())?;
        let dns_started = std::time::Instant::now();
        let addresses = resolve_public_addresses_v1(host).map_err(|error| error.to_string())?;
        let dns_microseconds = u64::try_from(dns_started.elapsed().as_micros()).unwrap_or(u64::MAX);
        let outcome = admit_research_url_v1(request, raw_url, &addresses, profile, policy)
            .map_err(|error| error.to_string())?;
        if outcome.admitted.is_none() {
            return Err(format!(
                "fresh URL admission rejected: {}",
                outcome.decision.reason_code
            ));
        }
        Ok(FreshAdmission {
            outcome,
            url_admission_microseconds: u64::try_from(admission_started.elapsed().as_micros())
                .unwrap_or(u64::MAX),
            dns_microseconds,
        })
    }

    fn redirected_admission_request(
        original: &ResearchUrlAdmissionRequestV1,
        raw_url: &str,
        index: usize,
    ) -> Result<ResearchUrlAdmissionRequestV1, String> {
        ResearchUrlAdmissionRequestV1 {
            schema_version: 1,
            request_id: format!("{}-redirect-{index}", original.request_id),
            organization_id: original.organization_id.clone(),
            case_id: original.case_id.clone(),
            source_candidate_id: format!("{}-redirect-{index}", original.source_candidate_id),
            url_protected_ref: format!("source-store:{}", sha256_bytes(raw_url.as_bytes())),
            source_policy_sha256: original.source_policy_sha256.clone(),
            network_profile_sha256: original.network_profile_sha256.clone(),
            request_sha256: ZERO_HASH.to_owned(),
        }
        .seal()
        .map_err(|error| error.to_string())
    }

    fn output_filename(input: &NetworkWorkerInputV1) -> Result<String, String> {
        match (&input.download_request, &input.download_intent) {
            (Some(request), Some(intent)) => semantic_download_filename_v1(
                &request.quarantine_artifact_id,
                intent.expected_class,
            )
            .map_err(|error| error.to_string()),
            (None, None) => Ok("research-body.bin".to_owned()),
            _ => Err("download output binding differs".to_owned()),
        }
    }

    fn classify_status(status: u16) -> FetchResultCodeV1 {
        match status {
            200..=299 => FetchResultCodeV1::Success,
            401 | 403 => FetchResultCodeV1::AuthenticationRequired,
            _ => FetchResultCodeV1::Rejected,
        }
    }

    fn prepare_empty_output_directory() -> Result<PathBuf, String> {
        let current = env::current_dir().map_err(|error| error.to_string())?;
        let metadata = fs::symlink_metadata(&current).map_err(|error| error.to_string())?;
        if metadata.file_type().is_symlink() {
            return Err("network worker output directory cannot be a symbolic link".to_owned());
        }
        let mut entries = fs::read_dir(&current).map_err(|error| error.to_string())?;
        if entries.next().is_some() {
            return Err("network worker output directory must be empty".to_owned());
        }
        Ok(current)
    }

    fn read_private_input() -> Result<NetworkWorkerInputV1, String> {
        let mut bytes = Vec::new();
        io::stdin()
            .take(MAX_PRIVATE_INPUT_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        if bytes.is_empty() || bytes.len() as u64 > MAX_PRIVATE_INPUT_BYTES {
            return Err("network worker private input is empty or oversized".to_owned());
        }
        serde_json::from_slice(&bytes).map_err(|error| format!("invalid private input: {error}"))
    }

    fn write_body(directory: &Path, filename: String, bytes: &[u8]) -> Result<String, String> {
        if filename.contains(['/', '\\', ':']) {
            return Err("network worker output filename is unsafe".to_owned());
        }
        let partial = directory.join("download.partial");
        let final_path = directory.join(&filename);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&partial)
            .map_err(|error| error.to_string())?;
        file.write_all(bytes).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        drop(file);
        fs::rename(&partial, &final_path).map_err(|error| error.to_string())?;
        Ok(filename)
    }

    fn current_executable_sha256() -> Result<String, String> {
        let path = env::current_exe().map_err(|error| error.to_string())?;
        let bytes = fs::read(path).map_err(|error| error.to_string())?;
        Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
    }

    fn decode_verifying_key(value: &str) -> Result<VerifyingKey, String> {
        if value.len() != 64 {
            return Err("network verifying key must be 32-byte hex".to_owned());
        }
        let mut bytes = [0_u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            let offset = index * 2;
            *byte = u8::from_str_radix(&value[offset..offset + 2], 16)
                .map_err(|_| "network verifying key is not hexadecimal".to_owned())?;
        }
        VerifyingKey::from_bytes(&bytes).map_err(|error| error.to_string())
    }

    fn unix_milliseconds() -> Result<u64, String> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())?;
        u64::try_from(elapsed.as_millis()).map_err(|_| "system time overflow".to_owned())
    }
}

#[cfg(windows)]
fn main() {
    windows_worker::main();
}

#[cfg(not(windows))]
fn main() {
    eprintln!("d2i-office600-network-worker requires Windows");
    std::process::exit(1);
}
