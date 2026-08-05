# WORK-500 Qwen3-4B Model Card

- Model ID: `Qwen/Qwen3-4B-GGUF`
- Revision: `bc640142c66e1fdd12af0bd68f40445458f3869b`
- Artifact: `Qwen3-4B-Q4_K_M.gguf`
- Quantization: Q4_K_M
- Artifact size: 2,497,280,256 bytes
- SHA-256: `7485fe6f11af29433bc51cab58009521f205840f5b4ae3a32fa7f92e8534fdf5`
- License: Apache-2.0
- Commercial use: permitted subject to the license
- Source: <https://huggingface.co/Qwen/Qwen3-4B-GGUF/tree/main>
- License source: <https://huggingface.co/Qwen/Qwen3-4B-GGUF/blob/bc640142c66e1fdd12af0bd68f40445458f3869b/LICENSE>
- Repository inclusion: excluded; supplied from a local approved cache

The GGUF embeds its tokenizer metadata, so the v1 descriptor binds the
tokenizer to the same immutable artifact hash. The provider limits context to
4096 tokens and output to 768 tokens. Known limitations include non-bitwise
live inference reproducibility, bounded English/Korean locale support, and a
narrow goal/situation/planning schema. Output is untrusted until strict host
validation succeeds.
