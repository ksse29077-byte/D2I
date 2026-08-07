# Office Capability Source Survey v1

Assessment date: 2026-08-08

This is a reproducible design survey, not an executor allowlist. Exact source
revisions and content digests are in
`sources/office/office-capability-sources.lock.json`. No surveyed repository is
vendored, downloaded at runtime, or granted production authority.

## Authority Order

1. Official application API or SDK documentation
2. Well-defined public file format
3. Mature open-source implementation
4. Community MCP implementation
5. UIA fallback

Public MCP names, tool names, argument schemas, and code are untrusted input.
They can inform a D2I-owned typed semantic operation, but the execution path
remains Policy, activation, KRN, and a trusted worker.

## Survey

| Source | Application / authority | Revision | License | Runtime / architecture | Tools | Exposure and advisory | D2I status |
| --- | --- | --- | --- | --- | ---: | --- | --- |
| Microsoft Excel Object Model | Excel / official | retrieved 2026-08-08 | Microsoft documentation terms | COM/VBA object model reference | 0 | Documentation only | approved as reference |
| Microsoft PowerPoint Object Model | PowerPoint / official | retrieved 2026-08-08 | Microsoft documentation terms | COM/VBA object model reference | 0 | Documentation only | approved as reference |
| Hancom Developer documentation | HWP/HWPX / official | retrieved 2026-08-08 | Hancom developer terms | SDK and document conversion reference | 0 | Documentation only | approved as reference |
| negokaz/excel-mcp-server | Excel / community | `1ff4340573c3e421920282da1602afd89f3bb282` | MIT | Go stdio MCP, file-level workbook operations | 42 | Caller-selected filesystem paths | eligible for adapter design |
| haris-musa/excel-mcp-server | Excel / community | `f51340ecd5778952405044b203d3a2d4c8a46833` | MIT | Python/openpyxl stdio MCP | 25 | Raw paths; historical `GHSA-j98m-w3xp-9f56` / `CVE-2026-40576` path traversal | rejected for runtime |
| mort-lab/excel-mcp | Excel / community | `59c84f57c51457dcc9515dd0661cf6700b5d6fa6` | MIT | Python stdio MCP | 34 | Python dependency and raw paths | eligible for adapter design |
| GongRzhe/Office-PowerPoint-MCP-Server | PowerPoint / community | `3631ba2ec0c24504476f78bf74d329c9be11caaa` | MIT | Archived Python/python-pptx stdio MCP | 37 | Raw paths, unmaintained revision | eligible for adapter design |
| ykuwai/ppt-mcp | PowerPoint / community | `192acd326779c21f2128bb45502d755a100de131` | unverified | Python COM automation | 156 | Broad COM and filesystem surface | research only |
| jenstangen1/pptx-xlsx-mcp | PowerPoint/Excel / community | `05bcb1b756caf51980301fc7e4f81ab587ff8b94` | unverified | Python file-level MCP | 40 | Raw paths and unverified license | research only |
| treesoop/hwp-mcp | HWP/HWPX / community | `4a93489d4f7dd316279b5f6f5d83014d9a8063f4` | MIT | TypeScript/Node stdio MCP | 35 | Raw paths and Node dependency | eligible for adapter design |
| mjyoo2/hwp-mcp | HWP / community | `4ef9df97a7a44c124c939ef0e4ccc7d4ca52917b` | unverified | Python COM automation | 140 | Broad COM/filesystem surface | research only |
| Dayoooun/hwpx-mcp | HWPX / community | `170b231d3c244a296e815ee6e725314b7163c5be` | MIT | TypeScript/Node HWPX file operations | 89 | Raw paths and Node dependency | eligible for adapter design |
| jkf87/hwp-mcp | HWP / community | `642035d4c721d2945123abdd702c5765007796bc` | unverified | Python COM automation | 30 | COM, raw paths, unverified license | research only |
| OfficeMCP/OfficeMCP | Word/Excel/PowerPoint / community | `188140dc784f53d66da566696072f47d29fa795a` | unverified | Python multi-application COM MCP | 14 | Broad application/filesystem surface | research only |
| theWDY/office-editor-mcp | Word/Excel/PowerPoint / community | `e8c93e76064103b2212ea6aad057ece8a1839231` | MIT | Python COM office editor | 90 | Raw paths and process launch | rejected for runtime |

Official references:

- [Excel Object Model](https://learn.microsoft.com/en-au/office/vba/api/overview/excel/object-model)
- [PowerPoint object reference](https://learn.microsoft.com/en-us/office/vba/api/powerpoint.slide)
- [Hancom Developer](https://developer.hancom.com/docsconverter/overview)
- [GitHub advisory GHSA-j98m-w3xp-9f56](https://github.com/advisories/GHSA-j98m-w3xp-9f56)

## Capability Findings

Useful design ideas are semantic operation grouping, bounded read/write
taxonomy, explicit workbook/document/presentation identity, post-operation
inspection, and separating application objects from transport. Unsafe ideas
are arbitrary file paths, arbitrary COM expressions, process launch, generated
Python or shell execution, arbitrary URL/network access, ambient credentials,
and treating a tool call response as verified completion.

The static survey did not establish a safe credential contract for any
community source. Credential behavior is therefore not adopted. Runtime
network, process, filesystem, and credential scope are denied unless a future
D2I-owned adapter defines and certifies narrower behavior.

## License and Dependency Treatment

MIT sources are design references only, so no source or transitive dependency
is copied into the product. Repositories without a verified license remain
`research_only`. Python and Node implementations may be inspected or run only
in a future isolated offline conformance lab; they are not root workspace or
production runtime dependencies. Replacement is the official API/SDK plus a
D2I-owned Rust contract and bounded application worker.

## Negative Policy

Synthetic `run_python`, shell, arbitrary filepath, arbitrary URL, remote
network, and unknown-license fixtures are deterministically rejected or held
research-only. There is intentionally no `approved_for_runtime` assessment
state in OFFICE-100.
