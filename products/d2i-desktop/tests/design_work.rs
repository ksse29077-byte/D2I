use d2i_design_intelligence::DesignArtifactFormatV1;
use d2i_desktop::{
    create_docx_document, create_pptx_template, default_document_resource_limits,
    extract_document_design_feature, extract_presentation_design_features, inspect_docx_document,
    inspect_hwpx_document, verify_design_feature_isolation,
};
use d2i_presentation_capability::default_presentation_resource_limits;
use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, String>;

fn repository_root() -> TestResult<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .map_err(|error| format!("repository root: {error}"))
}

#[test]
fn pptx_snapshot_extracts_normalized_design_features() -> TestResult {
    let root = tempfile_root("pptx")?;
    let path = root.join("corpus.pptx");
    let snapshot = create_pptx_template(
        &path,
        "presentation.design.fixture",
        5,
        &default_presentation_resource_limits(),
    )
    .map_err(|error| format!("PPTX fixture: {error}"))?;
    let features = extract_presentation_design_features(
        &snapshot,
        "org.alpha",
        "monthly_report",
        "family.alpha.monthly",
        1_000_000,
    )
    .map_err(|error| format!("feature extraction: {error}"))?;
    assert_eq!(features.len(), 5);
    assert!(features
        .iter()
        .all(|feature| feature.format == DesignArtifactFormatV1::Pptx));
    verify_design_feature_isolation(&features, "org.alpha")
        .map_err(|error| format!("tenant isolation: {error}"))?;
    std::fs::remove_dir_all(root).map_err(|error| format!("fixture cleanup: {error}"))?;
    Ok(())
}

#[test]
fn hwpx_snapshot_extracts_structure_without_raw_xml() -> TestResult {
    let path = repository_root()?.join("fixtures/office/document/hwpx-report-template.hwpx");
    let snapshot = inspect_hwpx_document(
        &path,
        "document.design.fixture",
        "artifact.design.hwpx",
        1,
        "backend.hwpx.file",
        1_000,
        &default_document_resource_limits(),
    )
    .map_err(|error| format!("HWPX inspect: {error}"))?;
    let feature = extract_document_design_feature(
        &snapshot,
        "org.alpha",
        "result_report",
        "family.alpha.result",
        800_000,
    )
    .map_err(|error| format!("HWPX feature: {error}"))?;
    assert_eq!(feature.format, DesignArtifactFormatV1::Hwpx);
    let serialized =
        serde_json::to_string(&feature).map_err(|error| format!("feature JSON: {error}"))?;
    assert!(!serialized.contains("<hp:"));
    assert!(!serialized.contains("Contents/section0.xml"));
    Ok(())
}

#[test]
fn docx_snapshot_extracts_structure_without_raw_xml() -> TestResult {
    let root = tempfile_root("docx")?;
    let path = root.join("corpus.docx");
    let limits = default_document_resource_limits();
    create_docx_document(&path, &limits).map_err(|error| format!("DOCX fixture: {error}"))?;
    let snapshot = inspect_docx_document(
        &path,
        "document.design.docx-fixture",
        "artifact.design.docx",
        1,
        "backend.docx.file",
        1_000,
        &limits,
    )
    .map_err(|error| format!("DOCX inspect: {error}"))?;
    let feature = extract_document_design_feature(
        &snapshot,
        "org.alpha",
        "internal_report",
        "family.alpha.internal",
        800_000,
    )
    .map_err(|error| format!("DOCX feature: {error}"))?;
    assert_eq!(feature.format, DesignArtifactFormatV1::Docx);
    let serialized =
        serde_json::to_string(&feature).map_err(|error| format!("feature JSON: {error}"))?;
    assert!(!serialized.contains("<w:"));
    assert!(!serialized.contains("word/document.xml"));
    std::fs::remove_dir_all(root).map_err(|error| format!("fixture cleanup: {error}"))?;
    Ok(())
}

#[test]
fn mixed_organization_features_fail_closed() -> TestResult {
    let root = tempfile_root("isolation")?;
    let path = root.join("corpus.pptx");
    let snapshot = create_pptx_template(
        &path,
        "presentation.design.isolation",
        1,
        &default_presentation_resource_limits(),
    )
    .map_err(|error| format!("PPTX fixture: {error}"))?;
    let mut alpha = extract_presentation_design_features(
        &snapshot,
        "org.alpha",
        "monthly_report",
        "family.alpha.monthly",
        1_000_000,
    )
    .map_err(|error| format!("alpha feature: {error}"))?;
    let beta = extract_presentation_design_features(
        &snapshot,
        "org.beta",
        "monthly_report",
        "family.beta.monthly",
        1_000_000,
    )
    .map_err(|error| format!("beta feature: {error}"))?;
    alpha.extend(beta);
    assert!(verify_design_feature_isolation(&alpha, "org.alpha").is_err());
    std::fs::remove_dir_all(root).map_err(|error| format!("fixture cleanup: {error}"))?;
    Ok(())
}

fn tempfile_root(label: &str) -> TestResult<PathBuf> {
    let path = std::env::temp_dir().join(format!(
        "d2i-office450-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |value| value.as_nanos())
    ));
    std::fs::create_dir_all(&path).map_err(|error| format!("fixture root: {error}"))?;
    Ok(path)
}
