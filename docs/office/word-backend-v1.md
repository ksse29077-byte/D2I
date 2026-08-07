# Word and DOCX Backend v1

DOCX is a first-class deterministic file backend. It shares the document
semantic contract with HWPX but has its own OOXML package parser/writer. This
path remains testable without Word and performs one new-generation mutation
followed by a fresh package reopen.

The live Word backend exists for installed-client compatibility. It runs in a
dedicated hidden child worker under the current interactive user, never a
service, session zero, ASP-style host, or arbitrary COM gateway. The worker
uses the fixed Word CLSID and a reviewed closed lowering for append paragraph,
insert table, and insert embedded image. Callers cannot provide a ProgID,
dispatch member, method name, macro, path expression, or script.

The worker binds the exact WINWORD path and SHA-256, current user/session,
source and destination generation, semantic operation, backend approval,
Policy decision, and one-shot activation. It forces `Visible = false`,
`DisplayAlerts = 0`, and `AutomationSecurity = 3`, then saves, closes, releases
COM references, quits, and waits for the owned process to exit. Pre-existing
Word process IDs are preserved. Timeout cleanup uses exact process image
identity and never kills by process name.

Completion installs an application-scoped WFP policy that permits Word
loopback and blocks IPv4 and IPv6 non-loopback egress. Provider, sublayer,
filters, ACLs, weights, conditions, and binary binding are exact-verified after
installation. A temporary zero-capability AppContainer SID receives only the
existing verifier ACL; the current user is not granted broad WFP read access.
The policy and profile are removed after success or failure and their state is
recorded in protected audit.

Word must already be installed and licensed as a desktop application. D2I does
not install, activate, bypass licensing, or automate it in a background
service. Legacy `.doc`, password-protected files, signed-document mutation,
macros, external templates, remote images, and active content are unsupported
or human exceptions in v1.
