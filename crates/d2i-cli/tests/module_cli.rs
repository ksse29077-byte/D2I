use d2i_cli::{run_with_io, EXIT_MODULE, EXIT_SUCCESS};
use serde_json::Value;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

fn module_root(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../modules")
        .join(name)
}

fn parse(bytes: &[u8]) -> Value {
    match serde_json::from_slice(bytes) {
        Ok(value) => value,
        Err(error) => panic!("CLI did not emit JSON: {error}"),
    }
}

#[test]
fn module_validate_and_reference_conformance_are_machine_readable() {
    let root = module_root("rule-based-work-reporter");
    let mut out = Vec::new();
    let mut err = Vec::new();
    assert_eq!(
        run_with_io(
            [
                OsString::from("d2ic"),
                OsString::from("module"),
                OsString::from("validate"),
                root.as_os_str().to_owned(),
                OsString::from("--json"),
            ],
            &mut out,
            &mut err,
        ),
        EXIT_SUCCESS,
        "{}",
        String::from_utf8_lossy(&err)
    );
    let validation = parse(&out);
    assert_eq!(validation["status"], "pass");
    assert_eq!(
        validation["module"]["module_id"],
        "rule-based-work-reporter"
    );
    assert_eq!(validation["network_requirement"], "denied");
    assert_eq!(validation["side_effect"], false);

    out.clear();
    err.clear();
    assert_eq!(
        run_with_io(
            [
                OsString::from("d2ic"),
                OsString::from("module"),
                OsString::from("conformance"),
                root.into_os_string(),
                OsString::from("--json"),
            ],
            &mut out,
            &mut err,
        ),
        EXIT_SUCCESS,
        "{}",
        String::from_utf8_lossy(&err)
    );
    let conformance = parse(&out);
    assert_eq!(conformance["success"], true);
    assert_eq!(conformance["report"]["status"], "pass");
    assert_eq!(conformance["report"]["skipped"], 0);
}

#[test]
fn arbitrary_module_execution_is_explicitly_unsupported() {
    let root = module_root("example-module");
    let mut out = Vec::new();
    let mut err = Vec::new();
    assert_eq!(
        run_with_io(
            [
                OsString::from("d2ic"),
                OsString::from("module"),
                OsString::from("conformance"),
                root.into_os_string(),
                OsString::from("--json"),
            ],
            &mut out,
            &mut err,
        ),
        EXIT_MODULE
    );
    let report = parse(&out);
    assert_eq!(report["status"], "unsupported");
    assert!(err.is_empty());
}
