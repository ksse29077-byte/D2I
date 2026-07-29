# Phase 1 Source Pack Contract

## Root and Manifest

A source pack is a readable directory containing UTF-8 `domain.yaml`.
`domain.yaml` is decoded into strict Rust types; unknown fields are errors.
The supported contract version is `d2i_version: "0.1"`. Domain versions use
`major.minor.patch` syntax. Domain and skill IDs use ASCII letters, digits,
hyphen, underscore, and period, and may not begin with punctuation.

Manifest paths are source-root-relative, use forward-slash separators, and are
limited to 4,096 UTF-8 bytes. Empty segments, control characters, colons,
backslashes, absolute or drive-prefixed paths, traversal, missing, unreadable,
or root-escaping references are errors. These lexical rules are applied
independently of the host operating system. High and critical skills must
declare a resolvable fallback.

## Inventory and Limits

Discovery accepts these case-insensitive extensions:

- `.md`
- `.txt`
- `.csv`
- `.json`
- `.jsonl`
- `.yaml`
- `.yml`

Every file is limited to 16 MiB. CSV and JSONL files are limited to 100,000
records. Symbolic links are rejected. Inventory entries are sorted by
slash-separated relative path.

Each file receives `sha256:<lowercase hex>`. The inventory hash is SHA-256 over
a version tag and unambiguous length-prefixed path, byte size, and content-hash
fields. Modification, creation, and access times are deliberately absent.

## Lock File

`d2ic validate --write-lock SOURCE_PACK` writes deterministic JSON to
`sources.lock`. The file contains:

- lock format version
- aggregate inventory hash
- sorted path, size, and content hash entries

`sources.lock` is excluded from discovery so writing it cannot change its own
hash.

## Parsing and Validation

Markdown and plain text are retained as bounded UTF-8 text. CSV is decoded into
headers and records. JSON, JSONL, and YAML are parsed into structured values.
Independent source errors accumulate instead of stopping at the first file.

JSON Schema validation uses draft 2020-12. Local relative `$ref` targets under
the source root are supported in memory. URL, root-absolute, and traversal
references are rejected without performing network or filesystem resolution.
Positive examples must satisfy the selected skill input schema; negative
examples must fail it.

Phase 1 also checks duplicate skill/procedure/rule/step/binding IDs, missing
manifest references, procedure `next` and executor targets, rule targets,
and fallback declarations.

## CLI Contract

```text
d2ic validate [--json] [--write-lock] [SOURCE_PACK]
d2ic inspect [--json] [SOURCE_PACK]
```

Human diagnostics include severity, stable code, file, line when available,
dotted field path when available, and remediation help. JSON mode emits the
same fields as one JSON object.

Exit codes:

- `0`: success
- `2`: command-line usage error
- `3`: source-pack validation failure
- `4`: output or lock-file I/O failure
