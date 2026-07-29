use d2i_desktop::run_windows_wfp_verifier_broker_service;
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let [mode, configuration] = arguments.as_slice() else {
        eprintln!("d2i-wfp-verifier-broker: invalid service command line");
        return ExitCode::from(2);
    };
    if mode != "__windows-wfp-broker-service" {
        eprintln!("d2i-wfp-verifier-broker: service mode is required");
        return ExitCode::from(2);
    }
    match run_windows_wfp_verifier_broker_service(Path::new(configuration)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("d2i-wfp-verifier-broker: {error}");
            ExitCode::from(2)
        }
    }
}
