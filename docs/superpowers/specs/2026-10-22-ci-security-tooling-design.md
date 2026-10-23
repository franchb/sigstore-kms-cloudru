# CI, Security, and Release Tooling — Design

Date: 2026-10-22
Status: Approved

## Decisions already made

This work lands on GitHub PR #1, branch `feat/cloudru-kms-plugin`
(`https://github.com/franchb/sigstore-kms-cloudru/pull/1`).

The branch gains the in-git CI, security, and release surface of
`github.com/franchb/sigstore-kms-yckms`, by copying that tree and renaming it
for Cloud.ru. Tool pins and action SHAs move to the latest release of the same
major already used in yckms. Go source changes are the SPDX header, the
`FuzzParseReference` test, the edits golangci-lint requires, and the tests that
bring statement coverage to 90%.

The first push to `main` publishes **v0.1.0**. There are no tags and no GitHub
releases today.

`CODEOWNERS` is exactly:

```
* @franchb @MichaelSBoop @evilchown755
```

`@wallrat1` is excluded. Inviting `@MichaelSBoop` and `@evilchown755` is later
operator work. They have no access to this repository today.

Codex (`gpt-6.1-sol`, read-only, 2026-10-22) decided the six points below.
The Claude CLI had no login, so it did not answer.

| Point | Decision |
| --- | --- |
| SPDX copyright | `Copyright 2026 franchb.` on every `.go` file. This module is original; every commit is franchb. |
| `CONTRIBUTING.md` review rule | State the two-approval, code-owner rule as the intended policy, and say it is unenforced until an operator adds the ruleset. |
| PR title | Retitle PR #1 to `feat: add the Cloud.ru sigstore KMS plugin`. |
| `go` line | Keep `go 1.27.0`. If a newer `go1.27` patch is published, add `toolchain go1.27.N` for that patch. If `1.27.0` is the newest patch, add no toolchain line. |
| Dependabot auto-merge | Copy the workflow. The job skips until the GitHub App variable is set. |
| `osv-scanner.toml` | Commit a comment-only file. Add `GO-2026-5932` only when a scan of this module reports it and this repo does not import `openpgp`. |

## Out of scope

- Creating or editing the GitHub ruleset.
- The bestpractices.dev questionnaire and any badge image in the README.
- Inviting collaborators, creating the Dependabot-merger GitHub App, turning on Issues, or changing 2FA.
- Applying to OSS-Fuzz, a ClusterFuzzLite storage repo, coverage HTML, or corpus pruning.
- Live calls to Cloud.ru.
- OS packages and container images of the plugin.
- Copying `dist/`, `.tool/`, `ruleset-21039437.backup.json`, `.remember/`, or the yckms design history under `docs/superpowers/`.

## What is copied

Copy these paths from yckms, then apply the renames in the next section.
Leave the workflow `name:` and job `name:` strings as they are in yckms, so a
later ruleset can require the same check contexts.

| Path | Role |
| --- | --- |
| `Makefile` | Shim from `make` to `task`, including `ci-bootstrap-go`. |
| `Taskfile.yaml` | Single source of truth for lint, test, fuzz, vuln scan, action lint, snapshot. |
| `.binny.yaml` | Pins for binny, task, golangci-lint, govulncheck, osv-scanner, betteralign, gosimports, goreleaser, actionlint, zizmor. |
| `.gitignore` | Ignores `.tool/`, `.tmp/`, `dist/`, coverage files, `.env`. |
| `.golangci.yml` | The yckms linter set, retargeted below. |
| `.goreleaser.yaml` | Six platform archives, checksums, syft SBOM, keyless cosign bundle. |
| `LICENSE` | Apache-2.0 text. The README already states that license. |
| `CODEOWNERS` | The line in Decisions. |
| `CONTRIBUTING.md` | Adapted in Docs. |
| `SECURITY.md` | Adapted in Docs. |
| `osv-scanner.toml` | Comment-only until a scan proves an ignore. |
| `ci/scripts/coverage.py` | Fails `task test` when total statement coverage is under the threshold. |
| `ci/scripts/diff.sh` | Fails when the tree is dirty. |
| `ci/scripts/govulncheck_module.py` | Module-graph govulncheck with the ignore file. |
| `ci/scripts/govulncheck_module_test.py` | Unit tests for that wrapper. |
| `.clusterfuzzlite/project.yaml` | `language: go`. |
| `.clusterfuzzlite/Dockerfile` | Digest-pinned `base-builder-go`, `GOTOOLCHAIN=auto`. |
| `.clusterfuzzlite/build.sh` | Compiles native `FuzzParseReference`. |
| `.github/dependabot.yml` | gomod, github-actions, and docker. |
| `.github/zizmor.yml` | zizmor config, copied as-is. |
| `.github/workflows/ci.yml` | `Check CI`, `Test (macos-latest)`, `Test (windows-latest)`, `govulncheck (module)`, `OSV Scanner`. |
| `.github/workflows/codeql.yml` | Job name `Analyze`, matrix language `go`, so the check context is `Analyze (go)`. |
| `.github/workflows/scorecards.yml` | Scorecard SARIF upload. |
| `.github/workflows/dependency-review.yml` | Job name `Dependency Review`. |
| `.github/workflows/pr-title.yml` | Job name `Conventional commit title`. |
| `.github/workflows/validate-github-actions.yaml` | actionlint and zizmor in CI. |
| `.github/workflows/vuln.yml` | Monday schedule plus `workflow_dispatch`. Runs all three scans. |
| `.github/workflows/cflite_pr.yml` | PR fuzz, 180s, code-change mode. Required to merge: no. |
| `.github/workflows/cflite_batch.yml` | Weekly batch fuzz, 600s. |
| `.github/workflows/release.yml` | Semantic-release dry-run, tag, GoReleaser, provenance. |
| `.github/workflows/dependabot-automerge.yml` | Auto-merge once the App exists. |

`release.yml` also has a job whose display name is `Check CI`. That job runs on
push to `main`. The PR required context of the same name is the job in `ci.yml`.
Keep both names.

## Rename rules

Apply these substitutions in copied files. Do them as text edits against the
copied content, then fix anything the substitutions do not cover.

| From | To |
| --- | --- |
| `sigstore-kms-yckms` | `sigstore-kms-cloudru` |
| `pkg/yckms` | `pkg/cloudru` |
| `github.com/franchb/sigstore-kms-yckms` | `github.com/franchb/sigstore-kms-cloudru` |
| `yckms://` | `cloudru://` |
| Yandex Cloud KMS wording in SECURITY, CONTRIBUTING, and release docs | Cloud.ru Advanced KMS |
| `YC_IAM_TOKEN`, `YC_OAUTH_TOKEN`, `YC_SERVICE_ACCOUNT_KEY_FILE` | `CLOUDRU_KMS_ENDPOINT`, `CLOUDRU_PROJECT_ID`, `CLOUDRU_AK`, `CLOUDRU_SK_FILE` |

`govulncheck_module.py` invokes `govulncheck -C pkg/yckms -scan=module -format json`
with no package pattern. The `-C` directory becomes `pkg/cloudru`. A pattern
such as `./...` makes govulncheck v1.7+ exit 2 in module mode.

`dependabot-automerge.yml` contains
`github.repository == 'franchb/sigstore-kms-yckms'`. That comparison becomes
`franchb/sigstore-kms-cloudru`. The rest of the `if` stays, including
`vars.DEPENDABOT_MERGER_CLIENT_ID != ''`, so the job skips while the App is absent.

`.goreleaser.yaml` sets `project_name`, the binary name, and
`release.github.name` to `sigstore-kms-cloudru`. Owner stays `franchb`.
The copied file has no `release.mode` key. Leave it that way: semantic-release
runs with `dry: true`, the workflow creates the git tag, and GoReleaser creates
the GitHub release. Archives include `LICENSE` and `README.md`. The binary
inside each archive is named `sigstore-kms-cloudru`. Builds stay `linux`,
`darwin`, and `windows`, each `amd64` and `arm64`, with `CGO_ENABLED=0`,
`-trimpath`, and ldflags `-s -w`. There is no `-X` version ldflag. Changelog
stays disabled.

Dependabot loses the `yandex-cloud` group. Ecosystems stay `gomod` at `/`,
`github-actions` at `/`, and `docker` at `/.clusterfuzzlite`. Commit prefix
stays `chore(deps)`. Schedule stays weekly, Monday, 12:00 UTC, with the same
cooldown numbers. The github-actions group still matches `*`.

## Pins

`.binny.yaml` keeps the same ten tools. Each `version.want` becomes the latest
release of the same major as the yckms pin, and no version goes below that pin:
binny v0.13.2, task v3.53.1, golangci-lint v2.14.0, govulncheck v1.8.0,
osv-scanner v2.6.0, betteralign v0.14.4, gosimports v0.3.8, goreleaser v2.17.1,
actionlint v1.7.12, zizmor v1.29.0. A new major waits for a later change. If a
newer release breaks `make check-ci`, keep the last pin that passed and record
the reason in the PR body.

Every `uses:` stays a full commit SHA with a trailing `# vX.Y.Z` comment.
Move each action to the latest release of the major named in the yckms comment,
and pin that release's commit. A new major waits for Dependabot. ClusterFuzzLite
`build_fuzzers` and `run_fuzzers` stay SHA-pinned on the v1 line, never `@v1`.
The GoReleaser action `version:` input equals the goreleaser pin in
`.binny.yaml`.

`.clusterfuzzlite/Dockerfile` uses
`FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:<digest>`. Resolve the digest
at implementation time. `GOTOOLCHAIN=auto` stays, so the `go` line in `go.mod`
is honored. `build.sh` installs
`github.com/AdamKorcz/go-118-fuzz-build@v0.0.0-20250520111509-a70c2aa677fa`
at image build time and does not add that module to `go.mod`. The compile line is:

```
compile_native_go_fuzzer github.com/franchb/sigstore-kms-cloudru/pkg/cloudru FuzzParseReference fuzz_parse_reference
```

`go.mod` stays `go 1.27.0`. Query the published Go 1.27 patch list. When a
patch newer than 1.27.0 exists, add `toolchain go1.27.N` for the newest one.
When 1.27.0 is current, leave the file without a toolchain line. Workflows keep
`go-version-file: go.mod`.

## Local gate

`make check-ci` remains a thin caller of the Taskfile. Order stays:

1. `lint` (gofmt clean, no `:` in filenames, `golangci-lint run` with tests included)
2. `validate-actions` (`actionlint`, then `zizmor --config .github/zizmor.yml .github`)
3. `verify-no-diff`
4. `test` (`go test -coverprofile` plus `coverage.py` with `COVERAGE_THRESHOLD: 90`)
5. `fuzz` (`go test ./pkg/cloudru -fuzz=FuzzParseReference -fuzztime=20s`)
6. `verify-no-diff`
7. `govulncheck` (`govulncheck ./...`, call graph)

`check-ci` does not run the module scan or OSV Scanner. Those are separate
required jobs, and `vuln.yml` runs all three on the schedule.

`task snapshot` runs
`goreleaser release --snapshot --clean --skip=sign,sbom`.

The `test` CI job, on `macos-latest` and `windows-latest`, runs
`go test -race -count=1 ./...` and does not call `coverage.py`.

Workflow shape copied with the files: `permissions: {}` at workflow level,
least permissions on each job, `persist-credentials: false` on checkout,
`step-security/harden-runner` with `egress-policy: audit` on Linux jobs,
`timeout-minutes` on every job, and a concurrency group keyed on workflow and
ref with `cancel-in-progress: true`. `release.yml` keeps
`cancel-in-progress: false`. Harden-runner stays off the macOS and Windows
test jobs, matching yckms. If harden-runner blocks the ClusterFuzzLite Docker
build, drop it on those two workflows only and say so in a comment at the top
of each file.

## Vulnerability gates

Three scans:

| Scan | Where | Blocks |
| --- | --- | --- |
| `govulncheck ./...` | inside `make check-ci` | reachable Go vulnerabilities |
| `govulncheck -C pkg/cloudru -scan=module` | required job `govulncheck (module)` | any Go vulnerability in the module graph, after ignores |
| `osv-scanner scan source --recursive .` | required job `OSV Scanner` | OSV, GHSA, and MAL advisories on `go.mod` / `go.sum`, after ignores |

The wrapper parses streaming JSON, collects `finding.osv` and aliases, and
drops an ID only when `osv-scanner.toml` has an `[[IgnoredVulns]]` entry whose
`ignoreUntil` is absent or strictly in the future (UTC date). An expired
`ignoreUntil` does not suppress the finding. Exit 1 when any finding remains.
A non-zero govulncheck, empty or invalid JSON, or a missing `osv-scanner.toml`
fails the job.

`osv-scanner.toml` is committed next to `go.mod` with this text and no
`[[IgnoredVulns]]` entries:

```toml
# An ignore is an [[IgnoredVulns]] entry with an id and a reason.
# Add one only after a scan of this module reports that id for a package
# this module does not import and that has no fixed version.
```

Run both scanners during implementation.

Add an ignore only when all three are true: the scan reports the ID, this
module's own packages do not import the vulnerable package, and no fixed module
version exists. `GO-2026-5932` (`golang.org/x/crypto/openpgp`, pulled in by
`github.com/sigstore/sigstore`) qualifies when this module does not import
`openpgp`. The reason text names that fact. A reachable finding is not ignored.
Removing the ignore entry must make `make govulncheck-module` fail when that
was the only thing keeping it green.

`vuln.yml` runs `make govulncheck`, `make govulncheck-module`, and
`make osv-scanner`. It has no `push` or `pull_request` trigger.

Dependency Review stays a pull-request diff scan.

## Fuzzing

Add `pkg/cloudru/reference_fuzz_test.go`:

```go
func FuzzParseReference(f *testing.F)
```

Seeds: a valid `cloudru://` plus lowercase UUID, the bare UUID, `""`, an
uppercase UUID, and a non-UUID string. The fuzz function calls `ParseReference`
and discards the error. The invariant is that the parser does not panic.
`go test ./...` executes the seeds. The 20-second random run is the `fuzz` task.

ClusterFuzzLite PR and batch workflows are copied and renamed. They are not
required to merge. Crashes are Actions artifacts. There is no storage-repo token.

## Lint, SPDX, and coverage

`.golangci.yml` keeps the yckms linter list, `version: "2"`, empty
`gosec.excludes`, `depguard` denying `log`, and the `_test.go` exclusions for
`gosec`, `errcheck`, `cyclop`, `forcetypeassert`, `noctx`, and `lll`.

Retarget:

- `testpackage.allow-packages`: `cloudru` and `main`.
- `exhaustruct.exclude`: drop `.*yckms\.ycKmsClient$`, `.*yckms\.SignerVerifier$`,
  and `.*go-sdk\.Config$`. Add `.*cloudru\.SignerVerifier$`. Keep the stdlib and
  `.*<anonymous>$` excludes. Add another exclude only after a lint run shows a
  partial composite literal that is idiomatic for that type.
- `ireturn.allow`: drop `github.com/yandex-cloud/go-sdk.Credentials`. Keep
  `error`, `empty`, `stdlib`, and
  `github.com/sigstore/sigstore/pkg/signature.Verifier`. Add a type only when
  a finding names a signature this package must return.
- `goheader`: yckms enables it with no template, so it checks nothing. Set the
  template to the header below, without the `//` prefixes, so a drifted header
  fails lint.

Every `.go` file, tests included, starts with:

```
// Copyright 2026 franchb.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
```

Fix every remaining golangci-lint finding. Prefer a scoped config exclusion
when the finding is a false positive for this repo. An inline `//nolint` is
for a single site the config cannot express, and `nolintlint` must accept it.

Statement coverage today is **79.1%** (`go test -covermode=atomic ./...`):
72.2% in `cmd/sigstore-kms-cloudru`, 79.6% in `pkg/cloudru`. `task test` gates
the total at 90. `main` is already `os.Exit(run(...))` and may stay at 0%.

Cover, with the existing httptest server and stubs, and with no live Cloud.ru call:

- `LoadSignerVerifier`
- `Public`, `Sign`, `CryptoSigner`, `SupportedAlgorithms`, `DefaultAlgorithm`
- the branches still under 90% in `loadSignerVerifier`, `VerifySignature`,
  `getPublicKey`, `run`, `describeKey`, `signDigest`, `post`, `validateKeyInfo`,
  `readSK`, `messageDigest`, `derSignature`, and `PublicKey`

`ParseReference` is already at 100%. If the total is still under 90% after
those functions are covered, add table tests for the remaining branches in
`client.go` and `kms.go`. The threshold stays 90.

## Release

`release.yml` triggers on `push` to `main`. Job order:

1. `Check CI` runs `make check-ci`.
2. `Determine version` checks out with `fetch-depth: 0` and runs
   `go-semantic-release/action` with `dry: true` and
   `allow-initial-development-versions: true`. That flag starts the first
   release at 0.1.0. In `applyChange`, a current version of 0.0.0 forces a
   minor bump, so the first release is 0.1.0 even when the analyzed commits
   have no `feat:`. The version output used for the tag has no `v` prefix.
3. When the version output is non-empty, the job creates `refs/tags/v<version>`
   on the pushed SHA.
4. `Publish release` checks out that tag and runs GoReleaser, then
   `actions/attest-build-provenance` on the archives and the checksum file.
   Permissions are `contents: write`, `id-token: write`, and
   `attestations: write`. On GoReleaser failure the tag is deleted.

During implementation, dry-run semantic-release against this branch's history
after the commits exist. The printed version must be `0.1.0`. Stop and adjust
the action inputs if it prints anything else. Do not push the tag from a
workstation.

The title of PR #1 becomes:

```
feat: add the Cloud.ru sigstore KMS plugin
```

Retitle with `gh pr edit` as soon as the title check is on the branch. The
`Conventional commit title` job fails until that title is set. This work does
not merge the PR.

## Docs

Keep the current README facts: `cloudru://<uuid>`, the four environment
variables, `EC_P256` / `SIGN_VERIFY`, the SK file mode, IAM rotation, NTP, and
Apache-2.0. Add three sections, with names substituted from the yckms README:

- Install, via `go install github.com/franchb/sigstore-kms-cloudru/cmd/sigstore-kms-cloudru@latest`
  and the library import path.
- Verifying releases: `cosign verify-blob` against the checksum bundle, with
  certificate identity
  `https://github.com/franchb/sigstore-kms-cloudru/.github/workflows/release.yml@refs/heads/main`
  and issuer `https://token.actions.githubusercontent.com`, then `sha256sum` and
  `gh attestation verify` for `franchb/sigstore-kms-cloudru`.
- Reproducing a snapshot: `task snapshot`, `CGO_ENABLED=0`, `-trimpath`.
  Snapshot checksums are unsigned.

`SECURITY.md` covers: only the latest release is supported; reports go to
GitHub private vulnerability reporting for this repository; the trust boundary
is this plugin and `pkg/cloudru` handling of `cloudru://` UUIDs and
`CLOUDRU_KMS_ENDPOINT`, `CLOUDRU_PROJECT_ID`, `CLOUDRU_AK`, and
`CLOUDRU_SK_FILE`; the plugin is a local CLI helper; Cloud.ru KMS and
`github.com/sigstore/sigstore` are reported upstream; the review date is
2026-10; release artifacts use keyless cosign and SLSA provenance.

`CONTRIBUTING.md` tells contributors to run `make check-ci`, lists what that
command runs, requires a conventional PR title, and tells reviewers to check
tests, scanners, and the absence of secrets. The two-approval and code-owner
sentences say the rule is the intended `main` policy and that this PR does not
create the ruleset that would enforce it.

## Verification

The change is done when all of the following are true on this branch:

- `make check-ci` exits 0, including statement coverage of at least 90% and a
  20-second `FuzzParseReference` run.
- `make govulncheck-module` exits 0. The command is
  `govulncheck -C pkg/cloudru -scan=module` with no package pattern. When an
  ignore was added, deleting that entry makes the command exit non-zero.
- `make osv-scanner` exits 0.
- `task validate-actions` exits 0.
- `task snapshot` writes six archives and a checksum file under `dist/`.
- `.clusterfuzzlite/Dockerfile` uses `FROM ...@sha256:...`.
- PR #1's title is `feat: add the Cloud.ru sigstore KMS plugin`.
- A dry-run of go-semantic-release on the branch history prints `0.1.0`.

CI on the PR must show these check names: `Check CI`, `Test (macos-latest)`,
`Test (windows-latest)`, `Analyze (go)`, `Dependency Review`,
`Conventional commit title`, `govulncheck (module)`, `OSV Scanner`.
ClusterFuzzLite may fail without blocking merge. `vuln.yml` does not run on the
PR.

## Later operator work

After this PR is on `main`, and outside this design:

- Invite `@MichaelSBoop` and `@evilchown755` before any ruleset requires a code-owner review.
- Create the `main` ruleset in the shape yckms uses: pull request required,
  two approvals, code owners, dismiss stale reviews, no bypass actors, no force-push,
  no deletion. Required checks are the eight names listed under Verification.
  Confirm each context string on the PR's Checks tab before creating the ruleset.
  Create it after this PR merges, so the new rules do not block the PR that adds the checks.
- Create the Dependabot merger GitHub App and set
  `vars.DEPENDABOT_MERGER_CLIENT_ID` and
  `secrets.DEPENDABOT_MERGER_PRIVATE_KEY` when auto-merge is wanted.
- Register the repository on bestpractices.dev in a separate session.
