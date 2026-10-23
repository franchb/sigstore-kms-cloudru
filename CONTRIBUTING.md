# Contributing

## Development

```sh
make check-ci
```

That runs format checks, golangci-lint, actionlint, zizmor, unit tests with
coverage of at least 90%, a 20s Go fuzz of `FuzzParseReference`, and call-graph
`govulncheck`.

PR CI also runs `govulncheck (module)` and `OSV Scanner`. Those fail on any
OSV/GHSA/MAL advisory in the module graph except IDs listed with a reason in
`osv-scanner.toml`.

## Pull requests

- Title must be a [conventional commit](https://www.conventionalcommits.org/)
  subject (`feat:`, `fix:`, `chore:`, `docs:`, `ci:`, `refactor:`, `test:`).
  The title becomes the squash-merge subject on `main`.
- Intended `main` policy, once an operator adds the ruleset: two approving
  reviews, a code owner must approve (`CODEOWNERS`), the author is not one of
  the approvals, and a new push dismisses stale approvals. This repository does
  not create that ruleset.

## Reviewer checklist

- Tests cover the change; `make check-ci` is green.
- No secrets in the tree or logs.
- New dependencies have a reason; module-scan and OSV Scanner are green.
- Do not add `osv-scanner.toml` ignores without an `id` and a `reason`.
