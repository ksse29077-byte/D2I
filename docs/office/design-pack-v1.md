# Organization Design Pack v1

`OrganizationDesignPackV1` is an immutable content-addressed result of an
approved corpus and deterministic compiler. It is configuration and evidence,
not execution authority.

## Contents

- organization profile and opaque artifact-class references
- font-role policy and approved fallback families
- typography hierarchy and size/spacing ranges
- spacing distributions and grid policy
- format-specific layout grammars and normalized slots
- table, chart, image, and logo policies
- template families, maturity, confidence, and eligible exemplar references
- rule provenance and separated holdout hashes

Font files, full artifact prose, raw XML, paths, scripts, credentials, and
unapproved assets are forbidden.

## Lifecycle

```text
approved corpus -> candidate (quarantine) -> holdout validation
-> signed OrganizationDesignPackApprovalV1 -> immutable production version
```

Approval binds exact organization, pack hash, allowed artifact classes,
environment, approver, signing key, issue time, and expiry. Mutation of the
payload, organization, class list, hash, signature, or validity fails closed.
Feedback produces `DesignPreferenceRecordV1` in quarantine and cannot modify a
production pack.

## Maturity

`template_lock` prefers exact or near-exact template reuse. `family_learned`
permits bounded variation inside one evidenced family.
`organization_learned` requires sufficient approved evidence across multiple
artifact classes. Insufficient evidence never causes invented company rules.

## Retrieval

The exemplar index is organization-bound and content-minimized. Exact
organization, artifact class, unit role, density, and requirements determine a
stable ranking. Style distance uses geometry, hierarchy, spacing, colors, and
density rather than copied business text.
