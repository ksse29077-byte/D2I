# Experimental Mojo Score Kernel

## Status

The candidate targets Mojo `1.0.0b2` and exports only
`d2i_score_match_masks_v1`. Mojo is not installed on the Phase 7 validation
host, so this source is not an accepted production backend.

Build on a host with the pinned compiler:

```powershell
.\backends\mojo\build.ps1 -Output .\build\d2i_case_score_mojo.dll
```

Hash the resulting library and run the controlled comparison:

```text
cargo run -p d2i-kernel --release --features mojo-backend --bin d2i-kernel-bench -- --candidate build/d2i_case_score_mojo.dll --hash sha256:... --out build/phase7-kernel-benchmark.json
```

The candidate is eligible only when output is exactly equal to Rust and the
same-host measured p50 speedup is at least `1.20x`. The package format and core
workspace never invoke Mojo.
