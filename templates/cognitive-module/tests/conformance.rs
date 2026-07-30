use d2i_example_module::ExampleModule;
use d2i_module_sdk::{run_fixture_suite, ConformanceStatus};
use std::path::Path;

#[test]
fn starter_template_passes_its_registered_fixture_suite() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let report = match run_fixture_suite(&ExampleModule, root) {
        Ok(report) => report,
        Err(error) => panic!("starter conformance failed to run: {error}"),
    };
    assert_eq!(report.status, ConformanceStatus::Pass);
    assert_eq!(report.failed, 0);
    assert_eq!(report.skipped, 0);
    assert!(!report.fixtures.is_empty());
}
