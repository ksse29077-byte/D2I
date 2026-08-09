use d2i_goal_compiler::GoalCompiler;
use d2i_module_sdk::{
    canonical_json_bytes, invoke_module, load_module_manifest, parse_json_strict,
    InvocationContext, ModuleInvocationEnvelope, SchemaCatalog,
};
use std::io::{Read, Write};
use std::process::ExitCode;

const MAX_STDIN_BYTES: usize = 2 * 1024 * 1024;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(()) => {
            eprintln!("goal-compiler e2e host rejected the bounded request");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<(), ()> {
    let mut input = Vec::new();
    std::io::stdin()
        .take(u64::try_from(MAX_STDIN_BYTES + 1).map_err(|_| ())?)
        .read_to_end(&mut input)
        .map_err(|_| ())?;
    if input.len() > MAX_STDIN_BYTES {
        return Err(());
    }
    let invocation: ModuleInvocationEnvelope = parse_json_strict(&input).map_err(|_| ())?;
    let root = std::env::current_dir().map_err(|_| ())?;
    let loaded = load_module_manifest(&root).map_err(|_| ())?;
    let schemas = SchemaCatalog::from_loaded(&loaded).map_err(|_| ())?;
    let context = InvocationContext {
        current_logical_tick: invocation.logical_sequence,
        current_observation_hash: invocation.source_observation_hash.clone(),
        current_plan_generation_id: invocation.plan_generation_id.clone(),
        allowed_trust_labels: loaded
            .manifest
            .security
            .accepted_trust_labels
            .iter()
            .cloned()
            .collect(),
        invocation_trust_labels: invocation.trust_labels.clone(),
    };
    let result =
        invoke_module(&GoalCompiler, &loaded, &schemas, &invocation, &context).map_err(|_| ())?;
    let bytes = canonical_json_bytes(&result).map_err(|_| ())?;
    std::io::stdout().write_all(&bytes).map_err(|_| ())
}
