# Security Score Validation Note

The current APK Scanner score begins at 100 and applies deductions for
debuggable builds, cleartext traffic, permission risk, insecure endpoints,
potential embedded secrets and excess exported components. These deductions
are implementation heuristics; the project must not describe them as
expert-validated or CVSS-calibrated until annotations have been collected.

The existing ML table generator includes a sensitivity analysis across
alternative weighting schemes. For independent validation of the APK Scanner
security score, use `scripts/evaluate-security-score-review.js` with actual
expert and CVSS values as documented in `docs/reproducibility.md`.
