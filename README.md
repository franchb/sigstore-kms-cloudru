# sigstore-kms-cloudru

Cloud.ru Advanced KMS provider for [Sigstore](https://github.com/sigstore/sigstore).

cosign and the other Sigstore tools sign with a key reference such as `awskms://` or `gcpkms://`. Those schemes are compiled into `github.com/sigstore/sigstore/pkg/signature/kms`. Cloud.ru Advanced has no provider there, so Sigstore execs a program on `PATH` named `sigstore-kms-<scheme>`. This repository is that program for `cloudru://`.

The CMK private key stays in Cloud.ru. The plugin hashes the message with SHA-256 locally, sends that digest to KMS, and checks signatures with the P-256 public key.

Module path: `github.com/franchb/sigstore-kms-cloudru`. License: Apache-2.0. Go 1.27.

## The two entry points

`cmd/sigstore-kms-cloudru` is the CLI plugin. Sigstore splits `cloudru://<uuid>` into the executable `sigstore-kms-cloudru` and the key id, then speaks the [cliplugin](https://github.com/sigstore/sigstore/tree/main/pkg/signature/kms/cliplugin) protocol. Responses go to stdout.

`pkg/cloudru` is the same signer for a Go program that links it in. It implements `kms.SignerVerifier`.

```go
import "github.com/franchb/sigstore-kms-cloudru/pkg/cloudru"
```

The only algorithm is `ECDSA_SHA_256`: ECDSA on NIST P-256, hash SHA-256. Create the CMK in the Advanced console as `EC_P256` / `SIGN_VERIFY`. `CreateKey` returns an error. This plugin does not mint keys.

A key reference is a lowercase UUID:

```text
cloudru://11111111-2222-3333-4444-555555555555
```

`LoadSignerVerifier` accepts that string or the bare UUID. Any other shape is rejected by `ParseReference`.

## Configure

The CLI plugin and `pkg/cloudru` both read the process environment.

| Variable | Meaning |
| --- | --- |
| `CLOUDRU_KMS_ENDPOINT` | HTTPS URL of the KMS API. A userinfo, query, or fragment is rejected. The client does not follow redirects and does not use an HTTP proxy. |
| `CLOUDRU_PROJECT_ID` | Project id. Sent as `X-Project-Id` and as the `/v1.0/{project_id}/kms/` path segment. |
| `CLOUDRU_AK` | Access key id of the IAM user. |
| `CLOUDRU_SK_FILE` | Path to the secret key file. The file is trimmed and read again on every KMS request. Keep it mode `600`, and do not commit it. |

Each call is `POST /v1.0/{project_id}/kms/{action}` with `SDK-HMAC-SHA256` authorization. The secret key is the HMAC key for that header. Error bodies from KMS are scrubbed of the access key and the secret key, then cut at 300 bytes.

On load the plugin calls `describe-key` and refuses a CMK whose `key_spec` is not `EC_P256` or whose `key_usage` is not `SIGN_VERIFY`. Signing calls `sign` with `message_type=DIGEST` and `signing_algorithm=ECDSA_SHA_256`. The public key comes from `get-publickey` as PKIX PEM. Verification is `ecdsa.VerifyASN1` on that key. The plugin does not call `/kms/verify`.

A per-call hash other than SHA-256 is an error. An unset hash, value 0, is hashed as SHA-256.

Use one IAM user for this CMK. It needs `kms:cmk:sign`, `kms:cmk:getPublicKey`, and `kms:cmk:get` (describe-key).

Rotation is two permanent keys on that user: create the second, install it on every signer, confirm, delete the first.

Hosts that run the plugin need NTP. The gateway rejects the request signature when the clock is off by about 15 minutes.

## Install and sign

```sh
go install github.com/franchb/sigstore-kms-cloudru/cmd/sigstore-kms-cloudru@latest
```

`go install` writes `sigstore-kms-cloudru` to `$(go env GOPATH)/bin`. That directory has to be on `PATH` before cosign runs, because Sigstore resolves the plugin with `exec.LookPath`.

```sh
export CLOUDRU_KMS_ENDPOINT='https://kms.example'
export CLOUDRU_PROJECT_ID='project-id'
export CLOUDRU_AK='access-key-id'
export CLOUDRU_SK_FILE='/run/secrets/cloudru-sk'

cosign sign-blob \
  --key cloudru://11111111-2222-3333-4444-555555555555 \
  --bundle artifact.sigstore.json \
  artifact
```

From Go:

```go
sv, err := cloudru.LoadSignerVerifier(ctx, "cloudru://11111111-2222-3333-4444-555555555555")
```

Unit tests stub KMS with `httptest`. The suite does not call Cloud.ru.

## CI

`make tools` installs the versions pinned in `.binny.yaml` under `.tool/`. `make check-ci` is the local gate, and it is the command `CONTRIBUTING.md` asks reviewers to run. It runs Task.

`check-ci` does this, in order:

1. `gofmt -l -s`, a check that no path contains `:`, and golangci-lint on the module, tests included.
2. actionlint and zizmor on `.github`.
3. A worktree status check, `ci/scripts/diff.sh`.
4. `go test` with a statement-coverage floor of 90% (`ci/scripts/coverage.py`).
5. Native fuzz of `FuzzParseReference` for 20 seconds.
6. The worktree status check again.
7. `govulncheck ./...` (call graph: reachable vulnerabilities).

`ci.yml` runs on pull requests and on pushes to `main`:

- `Check CI` on Ubuntu, the list above.
- `Test (macos-latest)` and `Test (windows-latest)`: `go test -race -count=1 ./...`. Those two jobs do not run the coverage script.
- `govulncheck (module)`: `govulncheck -C pkg/cloudru -scan=module`. The wrapper's own Python tests run first. A finding fails the job unless `osv-scanner.toml` lists that id or an alias. An `ignoreUntil` date applies only while it is still in the future (UTC). A missing ignore file, empty output, bad JSON, or a non-zero govulncheck status fails the job.
- `OSV Scanner`: `osv-scanner scan source --recursive .`, for OSV, GHSA, and MAL advisories, with the same ignore file.

Pull requests also run:

- `Conventional commit title` (`pr-title.yml`). The allowed types are `feat`, `fix`, `chore`, `docs`, `ci`, `refactor`, `test`, `perf`, `build`, and `revert`. On a squash merge, this title becomes the subject on `main`.
- `Dependency Review` on the pull request diff.
- `Lint` (`validate-github-actions.yaml`): zizmor. On a push to `main` this job runs when `.github/workflows` or `.github/actions` changed.
- `Analyze (go)`: CodeQL. The same job also runs on pushes to `main`.
- `ClusterFuzzLite (PR)`: build `FuzzParseReference` and run it for 180 seconds in `code-change` mode, with the address sanitizer (`.clusterfuzzlite`).

Scheduled jobs, all UTC:

| Workflow | When | What |
| --- | --- | --- |
| CodeQL | Monday 00:00, and on pull requests and pushes to `main` | `Analyze (go)` |
| ClusterFuzzLite batch | Monday 06:00, or `workflow_dispatch` | 600 second batch fuzz of `FuzzParseReference`, address sanitizer |
| `vuln.yml` | Monday 10:00, or `workflow_dispatch` | Call-graph govulncheck, the module scan, and OSV Scanner |
| Scorecard | Tuesday 07:20, plus pushes to `main` and branch-protection events | OpenSSF Scorecard. SARIF goes to code scanning |
| Dependabot | Monday 12:00 | Go modules, GitHub Actions, and the ClusterFuzzLite Dockerfile |

Dependabot commit prefix is `chore(deps)`. Go modules wait 7 days, and 14 days before a major. GitHub Actions updates are grouped into one pull request and wait 7 days. The ClusterFuzzLite image waits 7 days. Auto-merge (`dependabot-automerge.yml`) runs only in `franchb/sigstore-kms-cloudru`, and only after the repository variable `DEPENDABOT_MERGER_CLIENT_ID` is set.

`osv-scanner.toml` ignores one id: `GO-2026-5932` (`golang.org/x/crypto/openpgp`). Sigstore pulls in `x/crypto`, this module does not import `openpgp`, and the advisory has no fixed version. A new ignore needs an `id` and a `reason`.

## Workflow permissions and release signing

Each workflow starts at `permissions: {}`, except Scorecard, which sets `permissions: read-all`. A job then adds the scopes it needs. Actions are pinned to a full commit SHA, with the tag in a trailing comment. `actions/checkout` sets `persist-credentials: false`. Linux jobs run `step-security/harden-runner` with `egress-policy: audit`. The macOS and Windows test jobs leave harden-runner out, because that action has no runner for those operating systems.

`release.yml` runs on a push to `main`, and its concurrency group does not cancel an in-progress release. The publish path is:

1. `Check CI`.
2. go-semantic-release, with `allow-initial-development-versions`. While the repository is still at `0.0.0`, that flag publishes `0.1.0`. The dry run does not push a tag.
3. If that version is non-empty, `gh api` creates `refs/tags/v<version>`. The tool prints the version without a `v`.
4. GoReleaser publishes the GitHub release: linux, darwin, and windows, each on amd64 and arm64. Builds use `CGO_ENABLED=0` and `-trimpath`. The binary inside the archive is `sigstore-kms-cloudru` (`sigstore-kms-cloudru.exe` on Windows). Archives also contain `LICENSE` and this README. Checksums are signed with keyless cosign. Each archive has a [syft](https://github.com/anchore/syft) SBOM. GoReleaser's own changelog is disabled. The GitHub release notes are the changelog text from go-semantic-release.
5. `actions/attest-build-provenance` writes SLSA build provenance. The publish job's token can write contents, the OIDC id token, and attestations.
6. If GoReleaser fails, the workflow deletes the tag it created.

`CODEOWNERS` is `* @franchb @MichaelSBoop @evilchown755`. `CONTRIBUTING.md` records the intended review rule: two approving reviews, one of them a code owner, the author does not count, and a new push dismisses stale approvals. Adding that ruleset is operator work. This repository does not create it.

Report vulnerabilities through [GitHub private vulnerability reporting](https://github.com/franchb/sigstore-kms-cloudru/security/advisories/new). `SECURITY.md` has the scope. Cloud.ru KMS bugs go to Cloud.ru. Sigstore library bugs go to the [Sigstore project](https://github.com/sigstore/sigstore/security). The plugin is a local helper and does not listen on a port.

## Verifying releases

Release archives carry a keyless [cosign](https://github.com/sigstore/cosign) signature over the checksum file, plus SLSA build provenance.

```sh
cosign verify-blob \
  --bundle sigstore-kms-cloudru_<version>_checksums.txt.sigstore.json \
  --certificate-identity 'https://github.com/franchb/sigstore-kms-cloudru/.github/workflows/release.yml@refs/heads/main' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  sigstore-kms-cloudru_<version>_checksums.txt
sha256sum --check --ignore-missing sigstore-kms-cloudru_<version>_checksums.txt
gh attestation verify sigstore-kms-cloudru_<version>_linux_amd64.tar.gz \
  --repo franchb/sigstore-kms-cloudru \
  --signer-workflow franchb/sigstore-kms-cloudru/.github/workflows/release.yml
```

`<version>` is the release version without a leading `v`, as in the archive name GoReleaser writes. The GitHub Release title is `v<version>`.

## Reproducing a release archive locally

```sh
task snapshot
```

That is `goreleaser release --snapshot --clean --skip=sign,sbom`. Artifacts land in `dist/`. Snapshot checksums are not signed. To check a signature, use a published GitHub Release and the commands above.

