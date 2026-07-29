# Evaluation Plan And Report

Plan Ranker v1 requires a score of `1.0` for schema validity, deterministic
replay, hard-gate exclusion, rank-order accuracy, tie-break determinism,
duplicate rejection, untrusted-authority rejection, and critical-error freedom.

The unit and conformance suites cover normal, mixed, all-rejected, empty,
duplicate, stale-binding, malformed, boundary, reordered-input, and untrusted
cases. Final command results and the conformance report hash are recorded in the
pull request after execution.

A critical error is any ineligible or wrong selection, nondeterministic result,
duplicate acceptance, authority elevation, secret-bearing or schema-invalid
output, or failure to stop at a declared resource limit.
