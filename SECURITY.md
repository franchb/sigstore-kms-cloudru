# Security Policy

## Supported Versions

Only the latest released version of `sigstore-kms-cloudru` receives security fixes.

## Reporting a Vulnerability

Report security vulnerabilities through
[GitHub private vulnerability reporting](https://github.com/franchb/sigstore-kms-cloudru/security/advisories/new).

Please do not open a public issue for a security report.

Include, where possible: the affected version, a description of the impact, and
steps to reproduce. You will receive an acknowledgement within seven days.

## Scope

This project is a Cloud.ru Advanced KMS provider for Sigstore. Vulnerabilities
in the Cloud.ru KMS service itself should be reported to Cloud.ru; vulnerabilities
in Sigstore libraries should be reported to the [Sigstore project](https://github.com/sigstore/sigstore/security).

## Security review (2026-10)

Reviewed 2026-10.

Trust boundary: this repository's plugin and `pkg/cloudru` handling of
`cloudru://` key UUIDs and Cloud.ru credentials (`CLOUDRU_KMS_ENDPOINT`,
`CLOUDRU_PROJECT_ID`, `CLOUDRU_AK`, `CLOUDRU_SK_FILE`). The plugin is a local
CLI helper; it is not a network server.

Out of scope for this review (report upstream): Cloud.ru KMS itself,
and Sigstore libraries (`github.com/sigstore/sigstore`). See Scope above.

## Release Verification

Release artifacts are signed with [cosign](https://github.com/sigstore/cosign)
keyless signatures and carry SLSA build provenance. See the Verifying releases
section of `README.md`.
