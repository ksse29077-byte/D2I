# WORK-500 llama.cpp Runtime Card

- Runtime ID: `ggml-org/llama.cpp`
- Release: `b10275`
- Commit: `4308a4f035791f58ae111f56c39dac598bf476be`
- Executable: `llama-cli.exe`
- Executable SHA-256: `ea0809388e71270d1f238276ef123216a5a6d3663500185abe05d8cd72daceaf`
- Distribution ZIP SHA-256: `6029d1e839018b8edeaafff0da08952b68d0e4b7b4431c8aabe6c2dac8e66103`
- License: MIT
- Commercial use: permitted subject to the license
- Release source: <https://github.com/ggml-org/llama.cpp/releases/tag/b10275>
- License source: <https://github.com/ggml-org/llama.cpp/blob/master/LICENSE>
- Repository inclusion: excluded; supplied from a local approved cache

The executable is launched directly, without a shell, under a zero-capability
AppContainer and bounded Job Object. The host verifies the executable and
distribution identities, uses an environment allowlist, denies network
capabilities, limits memory to 8 GiB, enforces a 45-second invocation timeout,
and terminates the owned process tree on every outcome.
