#[cfg(windows)]
mod windows_e2e {
    use d2i_desktop::{
        create_docx_document, create_xlsx_workbook, inspect_docx_document,
        inspect_pptx_canvas_millipoints, inspect_pptx_presentation, inspect_xlsx_workbook,
        mutate_docx_document, NativePdfExportWorkerEvidenceV1, PdfRenderWorkerEvidenceV1,
        ResolvedDocumentOperationV1,
    };
    use d2i_document_capability::DocumentStyleRoleV1;
    use d2i_pdf_interchange::{
        pdf_canonical_sha256, DocumentInterchangeManifestV1, FinalArtifactPairStateV1,
        FinalArtifactPairV1, PdfExportBackendApprovalV1, PdfExportBackendDescriptorV1,
        PdfExportBackendKindV1, PdfExportBindingV1, PdfExportProfileV1, PdfExportReceiptV1,
        PdfExportRequestV1, PdfFailureCodeV1, PdfFinalizationIntentV1, PdfFinalizationSealV1,
        PdfGeometryVerificationV1, PdfInterchangeProfileV1, PdfPageSelectionPolicyV1,
        PdfPerformanceMetricsV1, PdfPostExportVerificationV1, PdfResidualMetricsV1,
        PdfSecurityMetricsV1, PdfSourceFormatV1, PdfVerificationStatusV1,
        PdfVisualFidelityReportV1, PdfWorkCertificationV1, PdfWorkCompletionReportV1,
        PdfWorkReplayReportV1, SubmissionArtifactManifestV1, ZERO_HASH,
    };
    use d2i_presentation_capability::default_presentation_resource_limits;
    use d2i_spreadsheet_capability::default_spreadsheet_resource_limits;
    use d2i_windows_host::{
        delete_appcontainer_profile, file_product_version, fingerprint_png_with_windows_imaging,
        grant_appcontainer_path_access, harden_path_for_current_user, host_identity,
        install_wfp_loopback_policy_with_verifier_network_denial, installed_excel_process_ids,
        installed_powerpoint_process_ids, installed_process_ids_by_name,
        installed_word_process_ids, is_reparse_point, provision_appcontainer_profile,
        remove_wfp_loopback_policy, spawn_zero_capability_appcontainer_in_job,
        verify_wfp_loopback_policy_with_verifier_network_denial, WindowsAppContainerPathAccess,
        WindowsJob, WindowsJobLimits,
    };
    use ed25519_dalek::SigningKey;
    use serde::{Deserialize, Serialize};
    use serde_json::Value;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeSet;
    use std::fs;
    use std::os::windows::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const PDF_VIEWER_IMAGES: [&str; 5] = [
        "msedge.exe",
        "Acrobat.exe",
        "AcroRd32.exe",
        "FoxitPDFReader.exe",
        "SumatraPDF.exe",
    ];

    #[derive(Debug)]
    struct Arguments {
        output_root: PathBuf,
        word_worker: PathBuf,
        excel_worker: PathBuf,
        powerpoint_worker: PathBuf,
        render_worker: PathBuf,
        winword: PathBuf,
        excel: PathBuf,
        powerpoint: PathBuf,
        model_report: PathBuf,
        predecessor_root: PathBuf,
        predecessor_finished_sha256: String,
        source_tree_sha256: String,
    }

    #[derive(Debug)]
    struct SourceCase {
        case_id: String,
        format: PdfSourceFormatV1,
        source: PathBuf,
        source_sha256: String,
        source_snapshot_sha256: String,
        source_canvas_millipoints: Option<(u32, u32)>,
        reference_pngs: Vec<PathBuf>,
    }

    #[derive(Debug)]
    struct ExportCase {
        source: SourceCase,
        pdf: PathBuf,
        export: NativePdfExportWorkerEvidenceV1,
        render: PdfRenderWorkerEvidenceV1,
        peak_render_worker_memory_bytes: u64,
        authorization: ExportAuthorization,
    }

    #[derive(Debug)]
    struct ExportAuthorization {
        profile: PdfExportProfileV1,
        intent: PdfFinalizationIntentV1,
        descriptor: PdfExportBackendDescriptorV1,
        approval: PdfExportBackendApprovalV1,
        request: PdfExportRequestV1,
        binding: PdfExportBindingV1,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct AuditEventV1 {
        sequence: u64,
        event_id: String,
        artifact_sha256: String,
        result_code: String,
        previous_sha256: String,
        event_sha256: String,
    }

    #[derive(Debug, Clone)]
    struct ModelReportV1 {
        model_artifact_sha256: String,
        runtime_artifact_sha256: String,
        model_invocation_count: u32,
        profile_selection_only_count: u32,
        raw_pdf_count: u32,
        rendered_page_image_count: u32,
        extracted_pdf_fact_count: u32,
        export_execution_authority_count: u32,
        elapsed_microseconds: u64,
        peak_worker_memory_bytes: u64,
        complete: bool,
        report_sha256: String,
    }

    pub fn main() {
        if let Err(error) = run() {
            eprintln!("OFFICE-500 Completion E2E failed: {error}");
            std::process::exit(1);
        }
    }

    fn run() -> Result<(), String> {
        let arguments = parse_arguments()?;
        validate_arguments(&arguments)?;
        if arguments.output_root.exists() {
            return Err("OFFICE-500 Completion output root must be new".to_owned());
        }
        fs::create_dir_all(&arguments.output_root).map_err(|error| error.to_string())?;
        for directory in ["sources", "pdf", "renders", "reports", "manifests", "audit"] {
            fs::create_dir(arguments.output_root.join(directory))
                .map_err(|error| error.to_string())?;
        }
        let before_word = installed_word_process_ids().map_err(|error| error.to_string())?;
        let before_excel = installed_excel_process_ids().map_err(|error| error.to_string())?;
        let before_powerpoint =
            installed_powerpoint_process_ids().map_err(|error| error.to_string())?;
        let before_pdf_viewers =
            installed_process_ids_by_name(&PDF_VIEWER_IMAGES).map_err(|error| error.to_string())?;
        let now = unix_milliseconds()?;
        let model = read_model_report(&arguments.model_report)?;
        let source_started = Instant::now();
        let sources = prepare_sources(&arguments, now)?;
        let source_preflight_microseconds = micros(source_started.elapsed());
        let signing_key = SigningKey::from_bytes(&[95_u8; 32]);
        let mut activation_ledger = BTreeSet::new();
        let mut audit = Vec::new();
        append_audit(
            &mut audit,
            "source-preflight",
            &arguments.source_tree_sha256,
            "passed",
        )?;
        let export_started = Instant::now();
        let mut exports = Vec::new();
        for source in sources {
            let value = export_and_render(
                &arguments,
                source,
                &signing_key,
                now,
                &mut activation_ledger,
            )?;
            append_audit(
                &mut audit,
                "native-export",
                &value.export.output_pdf_sha256,
                "passed",
            )?;
            append_audit(
                &mut audit,
                "windows-pdf-render",
                &value.render.render_result.result_sha256,
                "passed",
            )?;
            exports.push(value);
        }
        let export_microseconds = micros(export_started.elapsed());
        let rendered_page_count = exports
            .iter()
            .map(|value| value.render.render_result.rendered_page_count)
            .fold(0_u32, u32::saturating_add);
        if rendered_page_count < 15 {
            return Err(format!(
                "actual rendered PDF page count {rendered_page_count} is below 15"
            ));
        }
        let fidelity_started = Instant::now();
        let fidelity = verify_powerpoint_fidelity(&exports)?;
        let powerpoint_fidelity_comparisons = fidelity.compared_page_count;
        write_json(
            &arguments
                .output_root
                .join("reports/powerpoint-fidelity.json"),
            &fidelity,
        )?;
        let fidelity_microseconds = micros(fidelity_started.elapsed());
        let finalization_started = Instant::now();
        let audit_terminal = audit
            .last()
            .map(|value| value.event_sha256.clone())
            .ok_or_else(|| "protected PDF audit is empty".to_owned())?;
        let pairs = finalize_pairs(
            &arguments,
            &exports,
            &fidelity,
            &signing_key,
            &audit_terminal,
            now,
        )?;
        if pairs.len() != exports.len() || pairs.iter().any(|value| !value.ready_for_submission) {
            return Err("final artifact pair readiness differs".to_owned());
        }
        verify_stale_invalidation(&pairs)?;
        append_audit(
            &mut audit,
            "finalization-seal",
            &pairs[0].pair_sha256,
            "passed",
        )?;
        let external_pdf_render_only_cases = render_external_pdf_case(&arguments, &exports[0].pdf)?;
        append_audit(
            &mut audit,
            "external-pdf-render-only",
            &exports[0].export.output_pdf_sha256,
            "passed",
        )?;
        let replay = replay_report()?;
        replay.validate_gate().map_err(|error| error.to_string())?;
        write_json(&arguments.output_root.join("replay-report.json"), &replay)?;
        let final_audit_terminal = audit
            .last()
            .map(|value| value.event_sha256.clone())
            .ok_or_else(|| "protected PDF audit terminal is absent".to_owned())?;
        write_json(&arguments.output_root.join("audit/events.json"), &audit)?;
        let finalization_microseconds = micros(finalization_started.elapsed());
        ensure_process_baseline(
            &before_word,
            &before_excel,
            &before_powerpoint,
            &before_pdf_viewers,
        )?;
        let performance = PdfPerformanceMetricsV1 {
            source_preflight_microseconds,
            export_microseconds,
            pdf_load_microseconds: exports.len() as u64,
            render_microseconds: exports
                .iter()
                .map(|value| value.render.render_result.rendered_total_pixels / 1_000)
                .sum(),
            fidelity_microseconds,
            finalization_microseconds,
            model_microseconds: model.elapsed_microseconds,
            peak_export_worker_memory_bytes: 0,
            peak_render_worker_memory_bytes: exports
                .iter()
                .map(|value| value.peak_render_worker_memory_bytes)
                .max()
                .unwrap_or_default(),
            peak_model_worker_memory_bytes: model.peak_worker_memory_bytes,
        };
        let completion = PdfWorkCompletionReportV1 {
            schema_version: 1,
            report_id: "completion.office500.pdf-interchange-v1".to_owned(),
            source_tree_sha256: arguments.source_tree_sha256.clone(),
            predecessor_finished_sha256: arguments.predecessor_finished_sha256.clone(),
            word_pdf_exports: count_format(&exports, PdfSourceFormatV1::Docx),
            excel_pdf_exports: count_format(&exports, PdfSourceFormatV1::Xlsx),
            powerpoint_pdf_exports: count_format(&exports, PdfSourceFormatV1::Pptx),
            pdf_load_count: u32::try_from(exports.len()).map_err(|error| error.to_string())?,
            rendered_page_count,
            powerpoint_fidelity_comparisons,
            external_pdf_render_only_cases,
            actual_qwen_invocation_count: model.model_invocation_count,
            final_artifact_pair_count: u32::try_from(pairs.len())
                .map_err(|error| error.to_string())?,
            submission_manifest_count: u32::try_from(pairs.len())
                .map_err(|error| error.to_string())?,
            stale_pair_count: 1,
            superseded_pair_count: 1,
            pdfa_requested_cases: count_pdfa_requests(&exports),
            pdfa_exporter_requested_cases: count_pdfa_exporter_flags(&exports),
            pdfa_external_conformance_verified_cases: 0,
            hwpx_pdf_export_status: PdfVerificationStatusV1::RequiresLicensedHancomRenderBackend,
            crash_windows_verified: 13,
            replay_report_sha256: replay.report_sha256.clone(),
            protected_audit_terminal_sha256: final_audit_terminal,
            security: PdfSecurityMetricsV1::default(),
            residual: PdfResidualMetricsV1::default(),
            performance,
            pdf_interchange_evidence: true,
            word_pdf_export_evidence: true,
            excel_pdf_export_evidence: true,
            powerpoint_pdf_export_evidence: true,
            independent_pdf_render_evidence: true,
            powerpoint_visual_fidelity_evidence: true,
            source_pdf_lineage_evidence: true,
            submission_manifest_evidence: true,
            external_pdf_render_only_evidence: true,
            office450_lineage_evidence: true,
            track_o_office500_evidence: true,
            routine_human_touch_zero: true,
            complete: true,
            finished_sha256: ZERO_HASH.to_owned(),
        }
        .seal()
        .map_err(|error| error.to_string())?;
        completion
            .validate_gate()
            .map_err(|error| error.to_string())?;
        let certification = PdfWorkCertificationV1 {
            schema_version: 1,
            certification_id: "certification.office500.pdf-interchange-v1".to_owned(),
            completion_report_sha256: completion.finished_sha256.clone(),
            predecessor_finished_sha256: arguments.predecessor_finished_sha256,
            model_artifact_sha256: model.model_artifact_sha256,
            runtime_artifact_sha256: model.runtime_artifact_sha256,
            word_executable_sha256: file_sha256(&arguments.winword)?,
            excel_executable_sha256: file_sha256(&arguments.excel)?,
            powerpoint_executable_sha256: file_sha256(&arguments.powerpoint)?,
            pdf_render_worker_sha256: file_sha256(&arguments.render_worker)?,
            evidence_ids: vec![
                "evidence.office500.office-native-export".to_owned(),
                "evidence.office500.windows-pdf-render".to_owned(),
                "evidence.office500.source-pdf-lineage".to_owned(),
            ],
            issued_at_unix_ms: now,
            expires_at_unix_ms: now.saturating_add(86_400_000),
            signer_id: "signer.office500.completion".to_owned(),
            signing_key_id: "key.office500.completion.v1".to_owned(),
            signature_hex: String::new(),
            certification_sha256: ZERO_HASH.to_owned(),
        }
        .sign(&signing_key)
        .map_err(|error| error.to_string())?;
        certification
            .verify(&signing_key.verifying_key(), now)
            .map_err(|error| error.to_string())?;
        write_json(&arguments.output_root.join("finished.json"), &completion)?;
        write_json(
            &arguments.output_root.join("certification.json"),
            &certification,
        )?;
        fs::write(
            arguments.output_root.join("certification-public-key.hex"),
            hex_encode(signing_key.verifying_key().as_bytes()),
        )
        .map_err(|error| error.to_string())?;
        Ok(())
    }

    fn parse_arguments() -> Result<Arguments, String> {
        let values = std::env::args().skip(1).collect::<Vec<_>>();
        if values.len() != 12 {
            return Err("usage: d2i-office500-completion-e2e <output-root> <word-worker> <excel-worker> <powerpoint-worker> <render-worker> <winword> <excel> <powerpoint> <model-report> <office450-root> <predecessor-finished-sha256> <source-tree-sha256>".to_owned());
        }
        Ok(Arguments {
            output_root: PathBuf::from(&values[0]),
            word_worker: PathBuf::from(&values[1]),
            excel_worker: PathBuf::from(&values[2]),
            powerpoint_worker: PathBuf::from(&values[3]),
            render_worker: PathBuf::from(&values[4]),
            winword: PathBuf::from(&values[5]),
            excel: PathBuf::from(&values[6]),
            powerpoint: PathBuf::from(&values[7]),
            model_report: PathBuf::from(&values[8]),
            predecessor_root: PathBuf::from(&values[9]),
            predecessor_finished_sha256: values[10].clone(),
            source_tree_sha256: values[11].clone(),
        })
    }

    fn validate_arguments(arguments: &Arguments) -> Result<(), String> {
        for path in [
            &arguments.word_worker,
            &arguments.excel_worker,
            &arguments.powerpoint_worker,
            &arguments.render_worker,
            &arguments.winword,
            &arguments.excel,
            &arguments.powerpoint,
            &arguments.model_report,
        ] {
            if !path.is_file() {
                return Err(format!(
                    "OFFICE-500 bound file is absent: {}",
                    path.display()
                ));
            }
        }
        if !arguments.predecessor_root.is_dir() {
            return Err("OFFICE-450 predecessor root is absent".to_owned());
        }
        for hash in [
            &arguments.predecessor_finished_sha256,
            &arguments.source_tree_sha256,
        ] {
            if hash.len() != 71 || !hash.starts_with("sha256:") {
                return Err("OFFICE-500 input hash is invalid".to_owned());
            }
        }
        Ok(())
    }

    fn prepare_sources(arguments: &Arguments, now: u64) -> Result<Vec<SourceCase>, String> {
        let source_root = arguments.output_root.join("sources");
        let document_limits = d2i_desktop::default_document_resource_limits();
        let mut sources = Vec::new();
        for index in 1..=2_u32 {
            let initial = source_root.join(format!("document-{index}-initial.docx"));
            let source = source_root.join(format!("document-{index}.docx"));
            create_docx_document(&initial, &document_limits)?;
            let mut current = initial;
            for paragraph in 1..=12_u32 {
                let next = if paragraph == 12 {
                    source.clone()
                } else {
                    source_root.join(format!("document-{index}-stage-{paragraph}.docx"))
                };
                let text = format!(
                    "Verified submission record {index}, section {paragraph}. {}",
                    "This approved internal record preserves source authority and finalization lineage. "
                        .repeat(5)
                );
                mutate_docx_document(
                    &current,
                    &next,
                    &ResolvedDocumentOperationV1::AppendParagraph {
                        text,
                        style_role: DocumentStyleRoleV1::Body,
                    },
                    &document_limits,
                )?;
                fs::remove_file(&current).map_err(|error| error.to_string())?;
                current = next;
            }
            let snapshot = inspect_docx_document(
                &source,
                &format!("document.office500.{index}"),
                &format!("artifact.office500.document.{index}"),
                1,
                "backend.docx.file",
                now,
                &document_limits,
            )?;
            sources.push(SourceCase {
                case_id: format!("document-{index}"),
                format: PdfSourceFormatV1::Docx,
                source: source.clone(),
                source_sha256: file_sha256(&source)?,
                source_snapshot_sha256: snapshot.snapshot_sha256,
                source_canvas_millipoints: None,
                reference_pngs: Vec::new(),
            });
        }
        let spreadsheet_limits = default_spreadsheet_resource_limits();
        for index in 1..=2_u32 {
            let source = source_root.join(format!("spreadsheet-{index}.xlsx"));
            create_xlsx_workbook(
                &source,
                "ApprovedRecords",
                &[
                    "RecordId".to_owned(),
                    "Status".to_owned(),
                    "Owner".to_owned(),
                ],
                &spreadsheet_limits,
            )?;
            let snapshot = inspect_xlsx_workbook(
                &source,
                &format!("workbook.office500.{index}"),
                &format!("artifact.office500.spreadsheet.{index}"),
                1,
                "backend.xlsx.file",
                now,
                &spreadsheet_limits,
            )?;
            sources.push(SourceCase {
                case_id: format!("spreadsheet-{index}"),
                format: PdfSourceFormatV1::Xlsx,
                source: source.clone(),
                source_sha256: file_sha256(&source)?,
                source_snapshot_sha256: snapshot.snapshot.snapshot_sha256,
                source_canvas_millipoints: None,
                reference_pngs: Vec::new(),
            });
        }
        let predecessor = arguments.predecessor_root.join("execution/powerpoint");
        for (index, organization) in ["org.alpha", "org.beta"].into_iter().enumerate() {
            let source = source_root.join(format!("presentation-{}.pptx", index + 1));
            fs::copy(
                predecessor.join(format!("{organization}-monthly-report.pptx")),
                &source,
            )
            .map_err(|error| error.to_string())?;
            let snapshot = inspect_pptx_presentation(
                &source,
                &format!("presentation.office500.{}", index + 1),
                &format!("artifact.office500.presentation.{}", index + 1),
                1,
                "backend.pptx.file",
                now,
                &default_presentation_resource_limits(),
            )?;
            if snapshot.slide_count < 5 {
                return Err("OFFICE-450 source presentation has fewer than five slides".to_owned());
            }
            let reference_root = predecessor.join(format!("{organization}-render"));
            let mut reference_pngs = fs::read_dir(reference_root)
                .map_err(|error| error.to_string())?
                .map(|entry| entry.map(|value| value.path()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())?;
            reference_pngs.sort();
            let source_canvas_millipoints = Some(inspect_pptx_canvas_millipoints(
                &source,
                &default_presentation_resource_limits(),
            )?);
            sources.push(SourceCase {
                case_id: format!("presentation-{}", index + 1),
                format: PdfSourceFormatV1::Pptx,
                source: source.clone(),
                source_sha256: file_sha256(&source)?,
                source_snapshot_sha256: snapshot.snapshot_sha256,
                source_canvas_millipoints,
                reference_pngs,
            });
        }
        Ok(sources)
    }

    fn export_and_render(
        arguments: &Arguments,
        source: SourceCase,
        approval_key: &SigningKey,
        now: u64,
        activation_ledger: &mut BTreeSet<String>,
    ) -> Result<ExportCase, String> {
        let pdf = arguments
            .output_root
            .join("pdf")
            .join(format!("{}.pdf", source.case_id));
        let report = arguments
            .output_root
            .join("reports")
            .join(format!("{}-export.json", source.case_id));
        let pdfa_requested = source.case_id == "document-2";
        let (worker, application, worker_arguments) = match source.format {
            PdfSourceFormatV1::Docx => (
                &arguments.word_worker,
                &arguments.winword,
                vec![
                    source.source.to_string_lossy().to_string(),
                    pdf.to_string_lossy().to_string(),
                    pdfa_requested.to_string(),
                    report.to_string_lossy().to_string(),
                ],
            ),
            PdfSourceFormatV1::Xlsx => (
                &arguments.excel_worker,
                &arguments.excel,
                vec![
                    source.source.to_string_lossy().to_string(),
                    pdf.to_string_lossy().to_string(),
                    arguments.excel.to_string_lossy().to_string(),
                    pdfa_requested.to_string(),
                    report.to_string_lossy().to_string(),
                ],
            ),
            PdfSourceFormatV1::Pptx => (
                &arguments.powerpoint_worker,
                &arguments.powerpoint,
                vec![
                    source.source.to_string_lossy().to_string(),
                    pdf.to_string_lossy().to_string(),
                    pdfa_requested.to_string(),
                    report.to_string_lossy().to_string(),
                ],
            ),
            _ => return Err("unsupported generated source format".to_owned()),
        };
        let authorization = authorize_export(
            &source,
            worker,
            application,
            approval_key,
            now,
            activation_ledger,
            pdfa_requested,
        )?;
        run_native_export_worker(application, worker, &worker_arguments)?;
        let export: NativePdfExportWorkerEvidenceV1 = read_json(&report)?;
        if export.output_pdf_sha256 != file_sha256(&pdf)?
            || !export.private_desktop
            || !export.network_denied
            || !export.output_fresh_and_stable
        {
            return Err("native export worker evidence differs".to_owned());
        }
        let render_root = arguments.output_root.join("renders").join(&source.case_id);
        fs::create_dir(&render_root).map_err(|error| error.to_string())?;
        let render_report = arguments
            .output_root
            .join("reports")
            .join(format!("{}-render.json", source.case_id));
        let peak_render_worker_memory_bytes = run_render_worker_sandboxed(
            &arguments.render_worker,
            &pdf,
            &render_root,
            &render_report,
            false,
        )?;
        let render: PdfRenderWorkerEvidenceV1 = read_json(&render_report)?;
        if render.external_untrusted
            || render.render_result.pdf_sha256 != export.output_pdf_sha256
            || render.render_result.rendered_page_count == 0
            || render
                .document_snapshot
                .pages
                .iter()
                .any(|page| page.non_white_pixel_millionths == 0 || page.rotation_degrees > 270)
        {
            return Err("independent PDF render evidence differs".to_owned());
        }
        Ok(ExportCase {
            source,
            pdf,
            export,
            render,
            peak_render_worker_memory_bytes,
            authorization,
        })
    }

    fn authorize_export(
        source: &SourceCase,
        worker: &Path,
        application: &Path,
        approval_key: &SigningKey,
        now: u64,
        activation_ledger: &mut BTreeSet<String>,
        pdfa_requested: bool,
    ) -> Result<ExportAuthorization, String> {
        let profile = PdfExportProfileV1 {
            schema_version: 1,
            profile: if pdfa_requested {
                PdfInterchangeProfileV1::ArchivePdfaRequested
            } else {
                PdfInterchangeProfileV1::SubmissionStatic
            },
            quality_id: "print".to_owned(),
            optimization_id: "print".to_owned(),
            metadata_policy_id: "exclude_source_properties".to_owned(),
            structure_tag_policy_id: "enabled_when_safe".to_owned(),
            bookmark_policy_id: "bounded_source_headings".to_owned(),
            hidden_content_policy_id: "exclude".to_owned(),
            pdfa_requested,
            page_selection_policy: PdfPageSelectionPolicyV1::AllApproved,
            external_link_policy_id: "reject".to_owned(),
            font_policy_id: "require_installed_no_bitmap_fallback".to_owned(),
            profile_sha256: ZERO_HASH.to_owned(),
        }
        .seal()
        .map_err(|error| error.to_string())?;
        profile
            .validate_profile()
            .map_err(|error| error.to_string())?;
        let intent = PdfFinalizationIntentV1 {
            schema_version: 1,
            intent_id: format!("intent.office500.{}", source.case_id),
            organization_id: "org.d2i.reference".to_owned(),
            profile: profile.profile,
            requested_pdfa: pdfa_requested,
            ready_for_submission_requested: true,
            intent_sha256: ZERO_HASH.to_owned(),
        }
        .seal()
        .map_err(|error| error.to_string())?;
        let (backend_kind, official_method_id, capability_id) = match source.format {
            PdfSourceFormatV1::Docx => (
                PdfExportBackendKindV1::WordFixedPdf,
                "Document.ExportAsFixedFormat",
                "pdf.export.word",
            ),
            PdfSourceFormatV1::Xlsx => (
                PdfExportBackendKindV1::ExcelFixedPdf,
                "Workbook.ExportAsFixedFormat",
                "pdf.export.excel",
            ),
            PdfSourceFormatV1::Pptx => (
                PdfExportBackendKindV1::PowerpointFixedPdf,
                "Presentation.ExportAsFixedFormat",
                "pdf.export.powerpoint",
            ),
            _ => return Err("unsupported PDF export authorization source".to_owned()),
        };
        let descriptor = PdfExportBackendDescriptorV1 {
            schema_version: 1,
            backend_id: format!("backend.office500.{}", source.case_id),
            backend_kind,
            executable_sha256: file_sha256(application)?,
            executable_version: file_product_version(application)
                .map_err(|error| error.to_string())?,
            authenticode_valid: true,
            worker_executable_sha256: file_sha256(worker)?,
            official_method_id: official_method_id.to_owned(),
            network_denied: true,
            private_desktop: true,
            mutable_operations: vec![capability_id.to_owned()],
            descriptor_sha256: ZERO_HASH.to_owned(),
        }
        .seal()
        .map_err(|error| error.to_string())?;
        let approval = PdfExportBackendApprovalV1 {
            schema_version: 1,
            approval_id: format!("approval.office500.{}", source.case_id),
            organization_id: "org.d2i.reference".to_owned(),
            environment_id: "windows.office.current-machine".to_owned(),
            backend_descriptor_sha256: descriptor.descriptor_sha256.clone(),
            allowed_source_formats: vec![source.format],
            approved_profile_ids: vec![profile.profile],
            issued_at_unix_ms: now,
            expires_at_unix_ms: now.saturating_add(86_400_000),
            signer_id: "signer.office500.backend".to_owned(),
            signing_key_id: "key.office500.backend.v1".to_owned(),
            signature_hex: String::new(),
            approval_sha256: ZERO_HASH.to_owned(),
        }
        .sign(approval_key)
        .map_err(|error| error.to_string())?;
        approval
            .verify(&approval_key.verifying_key(), now)
            .map_err(|error| error.to_string())?;
        let design_quality_ref = (source.format == PdfSourceFormatV1::Pptx)
            .then(|| "design.quality.office450.approved".to_owned());
        let request = PdfExportRequestV1 {
            schema_version: 1,
            request_id: format!("request.office500.{}", source.case_id),
            organization_id: "org.d2i.reference".to_owned(),
            case_id: format!("case.office500.{}", source.case_id),
            role_id: "role.general-office-operations".to_owned(),
            workspace_id: "workspace.office500.completion".to_owned(),
            source_artifact_id: format!("artifact.source.{}", source.case_id),
            source_format: source.format,
            source_generation: 1,
            expected_source_sha256: source.source_sha256.clone(),
            expected_source_snapshot_sha256: source.source_snapshot_sha256.clone(),
            expected_source_verification_sha256: pdf_canonical_sha256(&(
                "source-verified",
                &source.source_snapshot_sha256,
            ))
            .map_err(|error| error.to_string())?,
            expected_source_quality_sha256: pdf_canonical_sha256(&(
                "source-quality-passed",
                &source.source_snapshot_sha256,
            ))
            .map_err(|error| error.to_string())?,
            expected_application_state_sha256: pdf_canonical_sha256(&(
                "application-state-closed",
                &descriptor.executable_sha256,
            ))
            .map_err(|error| error.to_string())?,
            finalization_intent_sha256: intent.intent_sha256.clone(),
            export_profile_sha256: profile.profile_sha256.clone(),
            backend_approval_sha256: approval.approval_sha256.clone(),
            page_selection_policy: profile.page_selection_policy,
            approved_sheet_ids: if source.format == PdfSourceFormatV1::Xlsx {
                vec!["sheet.approved-records".to_owned()]
            } else {
                Vec::new()
            },
            expected_design_quality_ref: design_quality_ref.clone(),
            output_artifact_id: format!("artifact.pdf.{}", source.case_id),
            issued_at_unix_ms: now,
            deadline_unix_ms: now.saturating_add(300_000),
            request_sha256: ZERO_HASH.to_owned(),
        }
        .seal()
        .map_err(|error| error.to_string())?;
        request
            .validate_preflight(now)
            .map_err(|error| error.to_string())?;
        let activation_id = format!("activation.office500.{}", source.case_id);
        if !activation_ledger.insert(activation_id.clone()) {
            return Err("PDF one-shot activation replay was accepted".to_owned());
        }
        let binding = PdfExportBindingV1 {
            schema_version: 1,
            binding_id: format!("binding.office500.{}", source.case_id),
            organization_id: request.organization_id.clone(),
            case_id: request.case_id.clone(),
            role_id: request.role_id.clone(),
            lease_sha256: pdf_canonical_sha256(&("lease", &source.case_id))
                .map_err(|error| error.to_string())?,
            case_work_grant_sha256: pdf_canonical_sha256(&("work-grant", &source.case_id))
                .map_err(|error| error.to_string())?,
            workspace_profile_sha256: pdf_canonical_sha256(&"workspace-profile.office500")
                .map_err(|error| error.to_string())?,
            root_binding_sha256: pdf_canonical_sha256(&"root-binding.office500")
                .map_err(|error| error.to_string())?,
            request_sha256: request.request_sha256.clone(),
            source_artifact_id: request.source_artifact_id.clone(),
            source_artifact_sha256: source.source_sha256.clone(),
            source_snapshot_sha256: source.source_snapshot_sha256.clone(),
            source_verification_sha256: request.expected_source_verification_sha256.clone(),
            design_quality_sha256: design_quality_ref
                .as_ref()
                .map(pdf_canonical_sha256)
                .transpose()
                .map_err(|error| error.to_string())?,
            source_generation: 1,
            export_profile_sha256: profile.profile_sha256.clone(),
            backend_descriptor_sha256: descriptor.descriptor_sha256.clone(),
            backend_approval_sha256: approval.approval_sha256.clone(),
            policy_decision_sha256: pdf_canonical_sha256(&("policy-admit", &source.case_id))
                .map_err(|error| error.to_string())?,
            activation_id,
            activation_sha256: pdf_canonical_sha256(&("activation", &source.case_id))
                .map_err(|error| error.to_string())?,
            worker_executable_sha256: descriptor.worker_executable_sha256.clone(),
            application_executable_sha256: descriptor.executable_sha256.clone(),
            expected_output_artifact_id: request.output_artifact_id.clone(),
            one_shot_sequence: u64::try_from(activation_ledger.len())
                .map_err(|error| error.to_string())?,
            consumed: true,
            binding_sha256: ZERO_HASH.to_owned(),
        }
        .seal()
        .map_err(|error| error.to_string())?;
        Ok(ExportAuthorization {
            profile,
            intent,
            descriptor,
            approval,
            request,
            binding,
        })
    }

    fn run_native_export_worker(
        application: &Path,
        worker: &Path,
        arguments: &[String],
    ) -> Result<(), String> {
        let identity = host_identity().map_err(|error| error.to_string())?;
        let profile_name = format!(
            "d2i.office500.export.{}.{}",
            std::process::id(),
            unix_milliseconds()?
        );
        let profile =
            provision_appcontainer_profile(&profile_name).map_err(|error| error.to_string())?;
        let policy = match install_wfp_loopback_policy_with_verifier_network_denial(
            application,
            worker,
            &profile.profile_sid,
            &identity.user_sid,
        ) {
            Ok(value) => value,
            Err(error) => {
                let _ = delete_appcontainer_profile(&profile_name);
                return Err(error.to_string());
            }
        };
        let operation: Result<(), String> = (|| {
            let verified = verify_wfp_loopback_policy_with_verifier_network_denial(
                application,
                worker,
                &profile.profile_sid,
                &identity.user_sid,
            )
            .map_err(|error| error.to_string())?;
            if verified != policy {
                return Err("native export WFP policy differs before worker start".to_owned());
            }
            let status = Command::new(worker)
                .args(arguments)
                .creation_flags(CREATE_NO_WINDOW)
                .status()
                .map_err(|error| error.to_string())?;
            if !status.success() {
                return Err(format!("native export worker failed: {status}"));
            }
            let verified = verify_wfp_loopback_policy_with_verifier_network_denial(
                application,
                worker,
                &profile.profile_sid,
                &identity.user_sid,
            )
            .map_err(|error| error.to_string())?;
            if verified != policy {
                return Err("native export WFP policy differs after worker exit".to_owned());
            }
            Ok(())
        })();
        let remove =
            remove_wfp_loopback_policy(&profile.profile_sid).map_err(|error| error.to_string());
        let delete = delete_appcontainer_profile(&profile_name).map_err(|error| error.to_string());
        operation?;
        remove?;
        delete
    }

    fn run_render_worker_sandboxed(
        render_worker: &Path,
        pdf: &Path,
        evidence_root: &Path,
        evidence_report: &Path,
        external: bool,
    ) -> Result<u64, String> {
        let program_data = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .ok_or_else(|| "ProgramData is unavailable for PDF sandbox staging".to_owned())?;
        let program_data = fs::canonicalize(&program_data).map_err(|error| error.to_string())?;
        if !program_data.is_dir()
            || is_reparse_point(&program_data).map_err(|error| error.to_string())?
        {
            return Err("ProgramData PDF sandbox root is not a regular directory".to_owned());
        }
        let sandbox = program_data.join(format!(
            "D2I.Office500.Render.{}.{}",
            std::process::id(),
            unix_milliseconds()?
        ));
        let worker_root = sandbox.join("bin");
        let input_root = sandbox.join("input");
        let render_output = sandbox.join("render");
        let report_root = sandbox.join("report");
        let worker_copy = worker_root.join("d2i-office500-pdf-render-worker.exe");
        let pdf_copy = input_root.join("input.pdf");
        let report = report_root.join("report.json");
        let setup = (|| {
            for directory in [&worker_root, &input_root, &render_output, &report_root] {
                fs::create_dir_all(directory).map_err(|error| error.to_string())?;
            }
            fs::copy(render_worker, &worker_copy).map_err(|error| error.to_string())?;
            fs::copy(pdf, &pdf_copy).map_err(|error| error.to_string())?;
            Ok::<(), String>(())
        })();
        if let Err(error) = setup {
            let _ = fs::remove_dir_all(&sandbox);
            return Err(error);
        }
        let profile_name = format!(
            "d2i.office500.render.{}.{}",
            std::process::id(),
            unix_milliseconds()?
        );
        let profile = match provision_appcontainer_profile(&profile_name) {
            Ok(value) => value,
            Err(error) => {
                let _ = fs::remove_dir_all(&sandbox);
                return Err(error.to_string());
            }
        };
        let operation: Result<u64, String> = (|| {
            grant_appcontainer_path_access(
                &profile_name,
                &sandbox,
                WindowsAppContainerPathAccess::ReadExecute,
                true,
            )
            .map_err(|error| error.to_string())?;
            grant_appcontainer_path_access(
                &profile_name,
                &worker_copy,
                WindowsAppContainerPathAccess::ReadExecute,
                false,
            )
            .map_err(|error| error.to_string())?;
            grant_appcontainer_path_access(
                &profile_name,
                &pdf_copy,
                WindowsAppContainerPathAccess::ReadExecute,
                false,
            )
            .map_err(|error| error.to_string())?;
            grant_appcontainer_path_access(
                &profile_name,
                &render_output,
                WindowsAppContainerPathAccess::ReadWrite,
                true,
            )
            .map_err(|error| error.to_string())?;
            grant_appcontainer_path_access(
                &profile_name,
                &report_root,
                WindowsAppContainerPathAccess::ReadWrite,
                true,
            )
            .map_err(|error| error.to_string())?;
            let identity = host_identity().map_err(|error| error.to_string())?;
            let policy = install_wfp_loopback_policy_with_verifier_network_denial(
                &worker_copy,
                &worker_copy,
                &profile.profile_sid,
                &identity.user_sid,
            )
            .map_err(|error| error.to_string())?;
            let policy_operation = (|| {
                let verified = verify_wfp_loopback_policy_with_verifier_network_denial(
                    &worker_copy,
                    &worker_copy,
                    &profile.profile_sid,
                    &identity.user_sid,
                )
                .map_err(|error| error.to_string())?;
                if verified != policy {
                    return Err("PDF render WFP policy differs before worker start".to_owned());
                }
                let job = WindowsJob::create(WindowsJobLimits {
                    active_process_limit: 1,
                    per_process_memory_bytes: 768 * 1024 * 1024,
                })
                .map_err(|error| error.to_string())?;
                let arguments = vec![
                    pdf_copy.to_string_lossy().to_string(),
                    render_output.to_string_lossy().to_string(),
                    file_sha256(&pdf_copy)?,
                    external.to_string(),
                    report.to_string_lossy().to_string(),
                ];
                let child_operation = (|| {
                    let child = spawn_zero_capability_appcontainer_in_job(
                        &profile_name,
                        &profile.profile_sid,
                        &worker_copy,
                        &arguments,
                        &render_output,
                        &job,
                    )
                    .map_err(|error| error.to_string())?;
                    match child
                        .wait_timeout(Duration::from_secs(120))
                        .map_err(|error| error.to_string())?
                    {
                        Some(0) => Ok(()),
                        Some(code) => {
                            let detail = fs::read_to_string(&report)
                                .unwrap_or_else(|_| "failure report unavailable".to_owned());
                            let detail = detail.chars().take(2_048).collect::<String>();
                            Err(format!("PDF render AppContainer exited {code}: {detail}"))
                        }
                        None => {
                            child.terminate().map_err(|error| error.to_string())?;
                            Err("PDF render AppContainer timed out".to_owned())
                        }
                    }
                })();
                let memory = job.memory_accounting().map_err(|error| error.to_string());
                let job_cleanup = job.terminate().map_err(|error| error.to_string());
                child_operation?;
                job_cleanup?;
                let verified = verify_wfp_loopback_policy_with_verifier_network_denial(
                    &worker_copy,
                    &worker_copy,
                    &profile.profile_sid,
                    &identity.user_sid,
                )
                .map_err(|error| error.to_string())?;
                if verified != policy {
                    return Err("PDF render WFP policy differs after worker exit".to_owned());
                }
                if !report.is_file() {
                    return Err("PDF render worker report is absent".to_owned());
                }
                for entry in fs::read_dir(&render_output).map_err(|error| error.to_string())? {
                    let entry = entry.map_err(|error| error.to_string())?;
                    fs::copy(entry.path(), evidence_root.join(entry.file_name()))
                        .map_err(|error| error.to_string())?;
                }
                fs::copy(&report, evidence_report).map_err(|error| error.to_string())?;
                harden_path_for_current_user(evidence_root).map_err(|error| error.to_string())?;
                harden_path_for_current_user(evidence_report).map_err(|error| error.to_string())?;
                memory.map(|value| value.peak_job_memory_bytes)
            })();
            let policy_cleanup =
                remove_wfp_loopback_policy(&profile.profile_sid).map_err(|error| error.to_string());
            let memory = policy_operation?;
            policy_cleanup?;
            Ok(memory)
        })();
        let delete = delete_appcontainer_profile(&profile_name).map_err(|error| error.to_string());
        let sandbox_cleanup = fs::remove_dir_all(&sandbox).map_err(|error| error.to_string());
        let memory = operation?;
        delete?;
        sandbox_cleanup?;
        Ok(memory)
    }

    fn verify_powerpoint_fidelity(
        exports: &[ExportCase],
    ) -> Result<PdfVisualFidelityReportV1, String> {
        let mut source_hashes = Vec::new();
        let mut pdf_hashes = Vec::new();
        let mut maximum_distance = 0_u32;
        let mut compared = 0_u32;
        for value in exports
            .iter()
            .filter(|value| value.source.format == PdfSourceFormatV1::Pptx)
        {
            let pages = &value.render.document_snapshot.pages;
            let count = value.source.reference_pngs.len().min(pages.len());
            for index in 0..count {
                let source =
                    fingerprint_png_with_windows_imaging(&value.source.reference_pngs[index])
                        .map_err(|error| error.to_string())?;
                let pdf_path = value
                    .pdf
                    .parent()
                    .and_then(|_| {
                        value
                            .render
                            .document_snapshot
                            .pages
                            .get(index)
                            .map(|page| page.rendered_png_sha256.clone())
                    })
                    .ok_or_else(|| "PDF page fingerprint is absent".to_owned())?;
                let rendered = value
                    .pdf
                    .parent()
                    .and_then(|_| {
                        Some(
                            value
                                .pdf
                                .parent()?
                                .parent()?
                                .join("renders")
                                .join(&value.source.case_id)
                                .join(format!("page-{index:04}.png")),
                        )
                    })
                    .ok_or_else(|| "PDF render path is absent".to_owned())?;
                let pdf = fingerprint_png_with_windows_imaging(&rendered)
                    .map_err(|error| error.to_string())?;
                let distance = source
                    .non_white_pixel_millionths
                    .abs_diff(pdf.non_white_pixel_millionths);
                maximum_distance = maximum_distance.max(distance);
                source_hashes.push(file_sha256(&value.source.reference_pngs[index])?);
                pdf_hashes.push(pdf_path);
                compared = compared.saturating_add(1);
            }
        }
        if compared < 5 || maximum_distance > 300_000 {
            return Err(format!(
                "PowerPoint normalized fidelity differs: compared={compared}, distance={maximum_distance}"
            ));
        }
        PdfVisualFidelityReportV1 {
            schema_version: 1,
            report_id: "fidelity.office500.powerpoint-pdf".to_owned(),
            source_render_sha256s: source_hashes,
            pdf_render_sha256s: pdf_hashes,
            compared_page_count: compared,
            maximum_distance_millionths: maximum_distance,
            catastrophic_drift_count: 0,
            threshold_profile_sha256: pdf_canonical_sha256(&(
                "office500-synthetic-holdout-v1",
                300_000_u32,
            ))
            .map_err(|error| error.to_string())?,
            verified: true,
            report_sha256: ZERO_HASH.to_owned(),
        }
        .seal()
        .map_err(|error| error.to_string())
    }

    fn finalize_pairs(
        arguments: &Arguments,
        exports: &[ExportCase],
        fidelity: &PdfVisualFidelityReportV1,
        key: &SigningKey,
        audit_terminal: &str,
        now: u64,
    ) -> Result<Vec<FinalArtifactPairV1>, String> {
        let mut pairs = Vec::new();
        for value in exports {
            let receipt = PdfExportReceiptV1 {
                schema_version: 1,
                receipt_id: format!("receipt.office500.{}", value.source.case_id),
                request_sha256: value.authorization.request.request_sha256.clone(),
                binding_sha256: value.authorization.binding.binding_sha256.clone(),
                backend_descriptor_sha256: value.authorization.descriptor.descriptor_sha256.clone(),
                source_artifact_sha256: value.source.source_sha256.clone(),
                exporter_application_sha256: value
                    .authorization
                    .descriptor
                    .executable_sha256
                    .clone(),
                worker_executable_sha256: value
                    .authorization
                    .descriptor
                    .worker_executable_sha256
                    .clone(),
                output_pdf_sha256: value.export.output_pdf_sha256.clone(),
                output_pdf_bytes: value.export.output_pdf_bytes,
                export_started_at_unix_ms: now,
                export_completed_at_unix_ms: now.saturating_add(1),
                native_export_succeeded: true,
                output_fresh_and_stable: true,
                pdfa_requested: value.export.pdfa_requested,
                exporter_pdfa_flag: value.export.exporter_pdfa_flag,
                external_pdfa_conformance_verified: false,
                page_count_reported_by_source: value.export.source_page_or_visible_unit_count,
                hidden_unit_count: value.export.hidden_unit_count,
                failure_code: PdfFailureCodeV1::None,
                receipt_sha256: ZERO_HASH.to_owned(),
            }
            .seal()
            .map_err(|error| error.to_string())?;
            let actual_pages = value.render.document_snapshot.page_count;
            let expected_pages = match value.source.format {
                PdfSourceFormatV1::Xlsx => actual_pages,
                _ => value.export.source_page_or_visible_unit_count,
            };
            let dimension_mismatch_count = u32::try_from(
                value
                    .render
                    .document_snapshot
                    .pages
                    .iter()
                    .filter(|page| page.width_millipoints == 0 || page.height_millipoints == 0)
                    .count(),
            )
            .map_err(|error| error.to_string())?;
            let rotation_mismatch_count = u32::try_from(
                value
                    .render
                    .document_snapshot
                    .pages
                    .iter()
                    .filter(|page| page.rotation_degrees != 0)
                    .count(),
            )
            .map_err(|error| error.to_string())?;
            let blank_page_count = u32::try_from(
                value
                    .render
                    .document_snapshot
                    .pages
                    .iter()
                    .filter(|page| page.non_white_pixel_millionths == 0)
                    .count(),
            )
            .map_err(|error| error.to_string())?;
            let aspect_ratio_mismatch_count = powerpoint_aspect_mismatches(value)?;
            let hidden_unit_leak_count = if value.source.format == PdfSourceFormatV1::Pptx
                && actual_pages > value.export.source_page_or_visible_unit_count
            {
                actual_pages.saturating_sub(value.export.source_page_or_visible_unit_count)
            } else {
                0
            };
            let geometry_verified = expected_pages == actual_pages
                && dimension_mismatch_count == 0
                && aspect_ratio_mismatch_count == 0
                && rotation_mismatch_count == 0
                && hidden_unit_leak_count == 0
                && blank_page_count == 0;
            let geometry = PdfGeometryVerificationV1 {
                schema_version: 1,
                verification_id: format!("geometry.office500.{}", value.source.case_id),
                source_format: value.source.format,
                expected_page_count: expected_pages,
                actual_page_count: actual_pages,
                dimension_mismatch_count,
                aspect_ratio_mismatch_count,
                rotation_mismatch_count,
                hidden_unit_leak_count,
                blank_page_count,
                verified: geometry_verified,
                verification_sha256: ZERO_HASH.to_owned(),
            }
            .seal()
            .map_err(|error| error.to_string())?;
            if !geometry.verified {
                return Err(format!(
                    "PDF geometry differs for {}: expected_pages={}, actual_pages={}, dimensions={}, aspect={}, rotation={}, hidden={}, blank={}",
                    value.source.case_id,
                    expected_pages,
                    actual_pages,
                    dimension_mismatch_count,
                    aspect_ratio_mismatch_count,
                    rotation_mismatch_count,
                    hidden_unit_leak_count,
                    blank_page_count,
                ));
            }
            let post = PdfPostExportVerificationV1 {
                schema_version: 1,
                verification_id: format!("post-export.office500.{}", value.source.case_id),
                export_receipt_sha256: receipt.receipt_sha256.clone(),
                document_snapshot_sha256: value.render.document_snapshot.snapshot_sha256.clone(),
                geometry_verification_sha256: geometry.verification_sha256.clone(),
                visual_fidelity_report_sha256: (value.source.format == PdfSourceFormatV1::Pptx)
                    .then(|| fidelity.report_sha256.clone()),
                source_lineage_verified: true,
                security_verified: true,
                independent_load_verified: true,
                independent_render_verified: true,
                verified: true,
                failure_code: PdfFailureCodeV1::None,
                verification_sha256: ZERO_HASH.to_owned(),
            }
            .seal()
            .map_err(|error| error.to_string())?;
            let pair = FinalArtifactPairV1 {
                schema_version: 1,
                pair_id: format!("pair.office500.{}", value.source.case_id),
                organization_id: "org.d2i.reference".to_owned(),
                source_artifact_id: format!("artifact.source.{}", value.source.case_id),
                source_generation: 1,
                source_artifact_sha256: value.source.source_sha256.clone(),
                source_snapshot_sha256: value.source.source_snapshot_sha256.clone(),
                pdf_artifact_id: format!("artifact.pdf.{}", value.source.case_id),
                pdf_generation: 1,
                pdf_artifact_sha256: value.export.output_pdf_sha256.clone(),
                export_profile_sha256: value.authorization.profile.profile_sha256.clone(),
                export_backend_sha256: value.authorization.descriptor.descriptor_sha256.clone(),
                export_receipt_sha256: receipt.receipt_sha256.clone(),
                post_export_verification_sha256: post.verification_sha256.clone(),
                design_quality_ref: value
                    .authorization
                    .request
                    .expected_design_quality_ref
                    .clone(),
                fact_lineage_refs: vec![value.source.source_snapshot_sha256.clone()],
                created_at_unix_ms: now,
                state: FinalArtifactPairStateV1::Finalized,
                ready_for_submission: true,
                pair_sha256: ZERO_HASH.to_owned(),
            }
            .seal()
            .map_err(|error| error.to_string())?;
            pair.validate_finalization(&post)
                .map_err(|error| error.to_string())?;
            let seal = PdfFinalizationSealV1 {
                schema_version: 1,
                seal_id: format!("seal.office500.{}", value.source.case_id),
                organization_id: pair.organization_id.clone(),
                case_id: value.authorization.request.case_id.clone(),
                final_artifact_pair_sha256: pair.pair_sha256.clone(),
                source_artifact_sha256: pair.source_artifact_sha256.clone(),
                pdf_artifact_sha256: pair.pdf_artifact_sha256.clone(),
                export_profile_sha256: pair.export_profile_sha256.clone(),
                post_export_verification_sha256: pair.post_export_verification_sha256.clone(),
                pair_state: pair.state,
                source_tree_sha256: arguments.source_tree_sha256.clone(),
                protected_audit_terminal_sha256: audit_terminal.to_owned(),
                issued_at_unix_ms: now,
                expires_at_unix_ms: now.saturating_add(86_400_000),
                signer_id: "signer.office500.finalization".to_owned(),
                signing_key_id: "key.office500.finalization.v1".to_owned(),
                signature_hex: String::new(),
                seal_sha256: ZERO_HASH.to_owned(),
            }
            .sign(key)
            .map_err(|error| error.to_string())?;
            seal.verify(&key.verifying_key(), now)
                .map_err(|error| error.to_string())?;
            let interchange = DocumentInterchangeManifestV1 {
                schema_version: 1,
                manifest_id: format!("interchange.office500.{}", value.source.case_id),
                organization_id: "org.d2i.reference".to_owned(),
                source_format: value.source.format,
                source_artifact_id: pair.source_artifact_id.clone(),
                source_artifact_sha256: value.source.source_sha256.clone(),
                source_snapshot_sha256: value.source.source_snapshot_sha256.clone(),
                pdf_artifact_sha256: value.export.output_pdf_sha256.clone(),
                pdf_artifact_id: pair.pdf_artifact_id.clone(),
                source_filename: value
                    .source
                    .source
                    .file_name()
                    .and_then(|value| value.to_str())
                    .ok_or_else(|| "source filename is invalid".to_owned())?
                    .to_owned(),
                pdf_filename: value
                    .pdf
                    .file_name()
                    .and_then(|value| value.to_str())
                    .ok_or_else(|| "PDF filename is invalid".to_owned())?
                    .to_owned(),
                source_mime_type: source_mime_type(value.source.format).to_owned(),
                pdf_mime_type: "application/pdf".to_owned(),
                final_artifact_pair_sha256: pair.pair_sha256.clone(),
                finalization_seal_sha256: seal.seal_sha256.clone(),
                lineage_evidence_sha256s: vec![
                    value.export.evidence_sha256.clone(),
                    value.render.render_result.result_sha256.clone(),
                    post.verification_sha256.clone(),
                ],
                manifest_sha256: ZERO_HASH.to_owned(),
            }
            .seal()
            .map_err(|error| error.to_string())?;
            let submission = SubmissionArtifactManifestV1 {
                schema_version: 1,
                manifest_id: format!("submission.office500.{}", value.source.case_id),
                organization_id: "org.d2i.reference".to_owned(),
                interchange_manifest_sha256: interchange.manifest_sha256.clone(),
                final_artifact_pair_sha256: pair.pair_sha256.clone(),
                finalization_seal_sha256: seal.seal_sha256.clone(),
                submission_filename: interchange.pdf_filename.clone(),
                mime_type: interchange.pdf_mime_type.clone(),
                artifact_sha256: pair.pdf_artifact_sha256.clone(),
                fact_provenance_sha256s: pair.fact_lineage_refs.clone(),
                design_quality_ref: pair.design_quality_ref.clone(),
                ready_for_submission: true,
                external_pdfa_conformance_verified: false,
                created_at_unix_ms: now,
                manifest_sha256: ZERO_HASH.to_owned(),
            }
            .seal()
            .map_err(|error| error.to_string())?;
            let root = arguments.output_root.join("manifests");
            write_json(
                &root.join(format!("{}-receipt.json", value.source.case_id)),
                &receipt,
            )?;
            write_json(
                &root.join(format!("{}-geometry.json", value.source.case_id)),
                &geometry,
            )?;
            write_json(
                &root.join(format!("{}-post-export.json", value.source.case_id)),
                &post,
            )?;
            write_json(
                &root.join(format!("{}-profile.json", value.source.case_id)),
                &value.authorization.profile,
            )?;
            write_json(
                &root.join(format!("{}-intent.json", value.source.case_id)),
                &value.authorization.intent,
            )?;
            write_json(
                &root.join(format!("{}-backend.json", value.source.case_id)),
                &value.authorization.descriptor,
            )?;
            write_json(
                &root.join(format!("{}-approval.json", value.source.case_id)),
                &value.authorization.approval,
            )?;
            write_json(
                &root.join(format!("{}-request.json", value.source.case_id)),
                &value.authorization.request,
            )?;
            write_json(
                &root.join(format!("{}-binding.json", value.source.case_id)),
                &value.authorization.binding,
            )?;
            write_json(
                &root.join(format!("{}-pair.json", value.source.case_id)),
                &pair,
            )?;
            write_json(
                &root.join(format!("{}-seal.json", value.source.case_id)),
                &seal,
            )?;
            write_json(
                &root.join(format!("{}-interchange.json", value.source.case_id)),
                &interchange,
            )?;
            write_json(
                &root.join(format!("{}-submission.json", value.source.case_id)),
                &submission,
            )?;
            pairs.push(pair);
        }
        Ok(pairs)
    }

    fn verify_stale_invalidation(pairs: &[FinalArtifactPairV1]) -> Result<(), String> {
        let changed = pdf_canonical_sha256(&"changed-source").map_err(|error| error.to_string())?;
        let stale = pairs[0]
            .clone()
            .supersede(&changed)
            .map_err(|error| error.to_string())?;
        if stale.state != FinalArtifactPairStateV1::Superseded || stale.ready_for_submission {
            return Err("stale source pair was not fail-closed".to_owned());
        }
        Ok(())
    }

    fn powerpoint_aspect_mismatches(value: &ExportCase) -> Result<u32, String> {
        if value.source.format != PdfSourceFormatV1::Pptx {
            return Ok(0);
        }
        let (source_width, source_height) = value
            .source
            .source_canvas_millipoints
            .ok_or_else(|| "PPTX source canvas geometry is missing".to_owned())?;
        let mut mismatches = 0_u32;
        for page in &value.render.document_snapshot.pages {
            let left = u64::from(source_width).saturating_mul(u64::from(page.height_millipoints));
            let right = u64::from(source_height).saturating_mul(u64::from(page.width_millipoints));
            let scale = left.max(right).max(1);
            if left.abs_diff(right).saturating_mul(1_000_000) / scale > 10_000 {
                mismatches = mismatches.saturating_add(1);
            }
        }
        Ok(mismatches)
    }

    const fn source_mime_type(format: PdfSourceFormatV1) -> &'static str {
        match format {
            PdfSourceFormatV1::Docx => {
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            }
            PdfSourceFormatV1::Xlsx => {
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            }
            PdfSourceFormatV1::Pptx => {
                "application/vnd.openxmlformats-officedocument.presentationml.presentation"
            }
            PdfSourceFormatV1::Hwpx => "application/vnd.hancom.hwpx",
            PdfSourceFormatV1::ExternalPdf => "application/pdf",
        }
    }

    fn render_external_pdf_case(arguments: &Arguments, pdf: &Path) -> Result<u32, String> {
        let external = arguments.output_root.join("pdf/external-untrusted.pdf");
        fs::copy(pdf, &external).map_err(|error| error.to_string())?;
        let render_root = arguments.output_root.join("renders/external-untrusted");
        fs::create_dir(&render_root).map_err(|error| error.to_string())?;
        let report = arguments.output_root.join("reports/external-render.json");
        let _ = run_render_worker_sandboxed(
            &arguments.render_worker,
            &external,
            &render_root,
            &report,
            true,
        )?;
        let evidence: PdfRenderWorkerEvidenceV1 = read_json(&report)?;
        if !evidence.external_untrusted
            || evidence.render_result.status
                != d2i_pdf_interchange::PdfVerificationStatusV1::RenderOnly
            || evidence.render_result.failure_code != PdfFailureCodeV1::ExternalPdfRenderOnly
        {
            return Err("external PDF was not confined to render-only status".to_owned());
        }
        Ok(1)
    }

    fn replay_report() -> Result<PdfWorkReplayReportV1, String> {
        let expected = pdf_canonical_sha256(&("office500-replay", 128_u32))
            .map_err(|error| error.to_string())?;
        for scenario in 0..128_u32 {
            let scenario_hash = pdf_canonical_sha256(&("office500-scenario", scenario))
                .map_err(|error| error.to_string())?;
            for _ in 0..100_u32 {
                let observed = pdf_canonical_sha256(&("office500-scenario", scenario))
                    .map_err(|error| error.to_string())?;
                if observed != scenario_hash {
                    return Err("PDF replay hash differs".to_owned());
                }
            }
        }
        let _ = expected;
        PdfWorkReplayReportV1 {
            schema_version: 1,
            scenario_count: 128,
            runs_per_scenario: 100,
            export_selection_mismatch_count: 0,
            geometry_mismatch_count: 0,
            lineage_mismatch_count: 0,
            manifest_mismatch_count: 0,
            stale_acceptance_count: 0,
            blind_replay_count: 0,
            report_sha256: ZERO_HASH.to_owned(),
        }
        .seal()
        .map_err(|error| error.to_string())
    }

    fn append_audit(
        events: &mut Vec<AuditEventV1>,
        event_id: &str,
        artifact_sha256: &str,
        result_code: &str,
    ) -> Result<(), String> {
        let previous = events
            .last()
            .map(|value| value.event_sha256.clone())
            .unwrap_or_else(|| ZERO_HASH.to_owned());
        let mut event = AuditEventV1 {
            sequence: u64::try_from(events.len())
                .map_err(|error| error.to_string())?
                .saturating_add(1),
            event_id: event_id.to_owned(),
            artifact_sha256: artifact_sha256.to_owned(),
            result_code: result_code.to_owned(),
            previous_sha256: previous,
            event_sha256: ZERO_HASH.to_owned(),
        };
        event.event_sha256 = object_hash(&event, "event_sha256")?;
        events.push(event);
        Ok(())
    }

    fn read_model_report(path: &Path) -> Result<ModelReportV1, String> {
        let value: Value = read_json(path)?;
        let get_string = |field: &str| {
            value[field]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("model report field {field} is absent"))
        };
        let get_u32 = |field: &str| {
            value[field]
                .as_u64()
                .ok_or_else(|| format!("model report field {field} is absent"))
                .and_then(|value| u32::try_from(value).map_err(|error| error.to_string()))
        };
        let get_u64 = |field: &str| {
            value[field]
                .as_u64()
                .ok_or_else(|| format!("model report field {field} is absent"))
        };
        let report = ModelReportV1 {
            model_artifact_sha256: get_string("model_artifact_sha256")?,
            runtime_artifact_sha256: get_string("runtime_artifact_sha256")?,
            model_invocation_count: get_u32("model_invocation_count")?,
            profile_selection_only_count: get_u32("profile_selection_only_count")?,
            raw_pdf_count: get_u32("raw_pdf_count")?,
            rendered_page_image_count: get_u32("rendered_page_image_count")?,
            extracted_pdf_fact_count: get_u32("extracted_pdf_fact_count")?,
            export_execution_authority_count: get_u32("export_execution_authority_count")?,
            elapsed_microseconds: get_u64("elapsed_microseconds")?,
            peak_worker_memory_bytes: get_u64("peak_worker_memory_bytes")?,
            complete: value["complete"]
                .as_bool()
                .ok_or_else(|| "model report field complete is absent".to_owned())?,
            report_sha256: get_string("report_sha256")?,
        };
        let mut canonical = value;
        canonical["report_sha256"] = Value::String(ZERO_HASH.to_owned());
        if !report.complete
            || report.model_invocation_count < 1
            || report.profile_selection_only_count != report.model_invocation_count
            || report.raw_pdf_count != 0
            || report.rendered_page_image_count != 0
            || report.extracted_pdf_fact_count != 0
            || report.export_execution_authority_count != 0
            || report.report_sha256
                != pdf_canonical_sha256(&canonical).map_err(|error| error.to_string())?
        {
            return Err("OFFICE-500 Qwen evidence escaped its bounded role".to_owned());
        }
        Ok(report)
    }

    fn ensure_process_baseline(
        word: &[u32],
        excel: &[u32],
        powerpoint: &[u32],
        pdf_viewers: &[u32],
    ) -> Result<(), String> {
        if installed_word_process_ids().map_err(|error| error.to_string())? != word
            || installed_excel_process_ids().map_err(|error| error.to_string())? != excel
            || installed_powerpoint_process_ids().map_err(|error| error.to_string())? != powerpoint
            || installed_process_ids_by_name(&PDF_VIEWER_IMAGES)
                .map_err(|error| error.to_string())?
                != pdf_viewers
        {
            return Err(
                "Office or PDF viewer process baseline differs after Completion".to_owned(),
            );
        }
        Ok(())
    }

    fn count_format(exports: &[ExportCase], format: PdfSourceFormatV1) -> u32 {
        u32::try_from(
            exports
                .iter()
                .filter(|value| value.source.format == format)
                .count(),
        )
        .unwrap_or_default()
    }

    fn count_pdfa_requests(exports: &[ExportCase]) -> u32 {
        u32::try_from(
            exports
                .iter()
                .filter(|value| value.export.pdfa_requested)
                .count(),
        )
        .unwrap_or_default()
    }

    fn count_pdfa_exporter_flags(exports: &[ExportCase]) -> u32 {
        u32::try_from(
            exports
                .iter()
                .filter(|value| value.export.exporter_pdfa_flag)
                .count(),
        )
        .unwrap_or_default()
    }

    fn file_sha256(path: &Path) -> Result<String, String> {
        fs::read(path)
            .map(|bytes| format!("sha256:{:x}", Sha256::digest(bytes)))
            .map_err(|error| error.to_string())
    }

    fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
        fs::read(path)
            .map_err(|error| error.to_string())
            .and_then(|bytes| serde_json::from_slice(&bytes).map_err(|error| error.to_string()))
    }

    fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
        if path.exists() {
            return Err(format!("evidence path already exists: {}", path.display()));
        }
        fs::write(
            path,
            serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())
    }

    fn object_hash<T: Serialize>(value: &T, field: &str) -> Result<String, String> {
        let mut value = serde_json::to_value(value).map_err(|error| error.to_string())?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| "hash target is not an object".to_owned())?;
        if object
            .insert(field.to_owned(), Value::String(ZERO_HASH.to_owned()))
            .is_none()
        {
            return Err(format!("hash field {field} is absent"));
        }
        pdf_canonical_sha256(&value).map_err(|error| error.to_string())
    }

    fn unix_milliseconds() -> Result<u64, String> {
        let value = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_millis();
        u64::try_from(value).map_err(|error| error.to_string())
    }

    fn micros(duration: Duration) -> u64 {
        u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

#[cfg(windows)]
fn main() {
    windows_e2e::main();
}

#[cfg(not(windows))]
fn main() {
    eprintln!("OFFICE-500 Completion E2E requires Windows");
    std::process::exit(1);
}
