# CI, Security, and Release Tooling Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Put the yckms CI, security, and release wiring on `feat/cloudru-kms-plugin` so PR #1 can publish v0.1.0 on its first push to `main`.

**Architecture:** Copy the yckms Taskfile, binny pins, workflows, and scanner scripts, then rename them for Cloud.ru. `Taskfile.yaml` is the local gate. GitHub workflows call `make` except for CodeQL, Scorecard, dependency review, and the release job. Go edits are the SPDX header, `FuzzParseReference`, lint fixes, and tests that lift statement coverage from 79.1% (204/258) to at least 90%.

**Tech Stack:** Go 1.27.0 with toolchain go1.27.3, Task v3.54.0, binny v0.13.4, golangci-lint v2.15.0, govulncheck v1.9.0, osv-scanner v2.7.0, GoReleaser v2.19.0, cosign, syft, go-semantic-release, zizmor v1.31.1, actionlint v1.7.12.

**Spec:** `docs/superpowers/specs/2026-10-22-ci-security-tooling-design.md` (Approved).

**Source tree to copy from:** `/home/iru/p/github.com/franchb/sigstore-kms-yckms`. Do not copy `dist/`, `.tool/`, `ruleset-21039437.backup.json`, `.remember/`, or that repo's `docs/`.

**Work on:** branch `feat/cloudru-kms-plugin`. Do not merge the PR. Do not push a tag. Do not create a GitHub ruleset.

---

## File map

| Path | Responsibility |
| --- | --- |
| `Makefile` | `make` shim onto `task`, plus `ci-bootstrap-go`. |
| `Taskfile.yaml` | lint, test+coverage, fuzz, govulncheck, module scan, osv-scanner, action lint, snapshot. |
| `.binny.yaml` | Pinned tool versions. |
| `.golangci.yml` | Linter set, retargeted at `cloudru`. |
| `ci/scripts/coverage.py` | Fails when `go tool cover -func` total is under the threshold. |
| `ci/scripts/diff.sh` | Fails when git status is dirty. |
| `ci/scripts/govulncheck_module.py` | Module-graph scan filtered by `osv-scanner.toml`. |
| `osv-scanner.toml` | Ignore list. Starts as comments. |
| `.goreleaser.yaml` | Six archives, checksums, SBOM, keyless cosign bundle. |
| `.clusterfuzzlite/` | Native Go fuzz build for `FuzzParseReference`. |
| `.github/workflows/` | CI, scanners, CodeQL, Scorecard, release, Dependabot auto-merge. |
| `pkg/cloudru/errors.go` | Sentinels so err113 can pass without changing error text that tests match. |
| `pkg/cloudru/reference_fuzz_test.go` | `FuzzParseReference`. |
| `pkg/cloudru/kms_cover_test.go` | Covers the uncovered `kms.go` statements. |
| `SECURITY.md`, `CONTRIBUTING.md`, `CODEOWNERS`, `LICENSE`, `README.md` | Policy and release docs. |

Covering the 32 uncovered statements in `pkg/cloudru/kms.go` moves the tree from 204/258 (79.1%) to 236/258 (91.5%). `main` may stay at 0%.

## Pinned versions (resolved 2026-10-22)

Tools, same major as yckms, not below the yckms pin:

| Tool | Pin |
| --- | --- |
| binny | v0.13.4 |
| task | v3.54.0 |
| golangci-lint | v2.15.0 |
| govulncheck | v1.9.0 |
| osv-scanner | v2.7.0 |
| betteralign | v0.15.4 |
| gosimports | v0.3.8 |
| goreleaser | v2.19.0 |
| actionlint | v1.7.12 |
| zizmor | v1.31.1 |

Action SHAs that move. Every other `uses:` SHA in the yckms workflows stays, including ClusterFuzzLite `v1` at `884713a6c30a92e5e8544c39945cd7cb630abcd1` (the `v1` tag has not moved).

| Action | New pin |
| --- | --- |
| `step-security/harden-runner` | `dc2769abcc0fcfbadfc1df54081c1608579ef6b2` `# v2.22.2` |
| `anchore/sbom-action/download-syft` | `66cbf4bc1f1c0d2edc94016e65bc221b6bb0ad6c` `# v0.24.3` |
| `goreleaser/goreleaser-action` | `a4f02ab5355a589de60d917a659ce617ed19b3de` `# v7.3.0` |
| `actions/create-github-app-token` | `64ab729a6294000f5aa4a4bc0b73d1f32bc45510` `# v3.3.0` |
| `zizmorcore/zizmor-action` | `85b2b9fb8e3325e7a23d7d0a9d7ba5ae0f999e3e` `# v0.7.1` |
| `ossf/scorecard-action` | `fa7117db83c52d787ae5a89f350999701505d78e` `# v2.5.0` |
| `actions/upload-artifact` | `cf430e030ddbb5b0abf93d22962f4752f3646cd9` `# v7.0.2` |
| `github/codeql-action/*` | `9b3254085494b55a0f7c4c2b3d2d52cc712ce370` `# v4.39.1` |

`goreleaser-action` `version:` becomes `v2.19.0`.

Base image digest for `gcr.io/oss-fuzz-base/base-builder-go:latest` on 2026-10-22:

```
sha256:1dbadefbb28c6bfd796c64d9c2115977deb8f19494533cc5a3b724c3441df23d
```

Go toolchain: `go1.27.3` is the newest 1.27 patch. Keep `go 1.27.0` and add `toolchain go1.27.3`.

---

### Task 1: SPDX header on every Go file

**Files:**
- Modify: every `*.go` under `cmd/` and `pkg/`

The header is inserted above the existing `package` line. Do not change any other line in this task.

- [ ] **Step 1: Insert the header**

```bash
python3 << 'PY'
from pathlib import Path
header = """// Copyright 2026 franchb.
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

"""
for path in Path(".").rglob("*.go"):
    if any(part in {".git", ".tool"} for part in path.parts):
        continue
    text = path.read_text()
    if text.startswith("// Copyright 2026 franchb."):
        continue
    path.write_text(header + text)
    print(path)
PY
```

- [ ] **Step 2: Tests still pass**

Run: `go test ./... -count=1`

Expected: both packages `ok`.

- [ ] **Step 3: Commit**

```bash
git add cmd pkg
git commit -m "chore: add Apache-2.0 SPDX headers"
```

---

### Task 2: Fuzz the reference parser

**Files:**
- Create: `pkg/cloudru/reference_fuzz_test.go`

- [ ] **Step 1: Write the fuzz test**

```go
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

package cloudru

import "testing"

func FuzzParseReference(f *testing.F) {
	const id = "0d0466b0-e727-4d9c-b35d-f84bb474a37f"
	f.Add("cloudru://" + id)
	f.Add(id)
	f.Add("")
	f.Add("cloudru://" + "0D0466B0-E727-4D9C-B35D-F84BB474A37F")
	f.Add("not-a-uuid")
	f.Fuzz(func(_ *testing.T, ref string) {
		_, _ = ParseReference(ref)
	})
}
```

- [ ] **Step 2: Run the seeds, then 20 seconds of fuzzing**

Run: `go test ./pkg/cloudru -run '^$' -fuzz=FuzzParseReference -fuzztime=20s`

Expected: `PASS`. The fuzz function must not panic.

- [ ] **Step 3: Commit**

```bash
git add pkg/cloudru/reference_fuzz_test.go
git commit -m "test: fuzz Cloud.ru key reference parsing"
```

---

### Task 3: Cover the rest of kms.go

**Files:**
- Create: `pkg/cloudru/kms_cover_test.go`
- Test: `go test ./pkg/cloudru -cover`

`testKeyID`, `signerService`, `kmsStub`, and `marshalPKIXPEM` already exist in this package. These tests call them.

- [ ] **Step 1: Write the failing coverage tests**

```go
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

package cloudru

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sigstore/sigstore/pkg/signature/options"
)

func TestLoadSignerVerifierRequiresConfig(t *testing.T) {
	t.Setenv("CLOUDRU_KMS_ENDPOINT", "")
	t.Setenv("CLOUDRU_PROJECT_ID", "")
	t.Setenv("CLOUDRU_AK", "")
	t.Setenv("CLOUDRU_SK_FILE", "")
	_, err := LoadSignerVerifier(context.Background(), "cloudru://"+testKeyID)
	if err == nil {
		t.Fatal("LoadSignerVerifier succeeded without config")
	}
}

func TestLoadSignerVerifierRejectsBadReference(t *testing.T) {
	t.Parallel()
	_, err := loadSignerVerifier(context.Background(), "cloudru://not-a-uuid", &service{})
	if err == nil {
		t.Fatal("expected a bad reference to fail before describe")
	}
}

func TestLoadSignerVerifierDescribeError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	_, err := loadSignerVerifier(context.Background(), testKeyID, signerService(t, srv))
	if err == nil {
		t.Fatal("expected describe-key failure")
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

func TestMessageDigestEdges(t *testing.T) {
	t.Parallel()
	if _, err := messageDigest(nil, nil, nil); err == nil {
		t.Fatal("nil message should fail")
	}
	if _, err := messageDigest(errReader{}, nil, nil); err == nil {
		t.Fatal("reader error should fail")
	}
	sum := sha256.Sum256([]byte("x"))
	got, err := messageDigest(nil, sum[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, sum[:]) {
		t.Fatal("precomputed digest was not returned")
	}
}

func TestDerSignatureRejectsGarbage(t *testing.T) {
	t.Parallel()
	if _, err := derSignature([]byte{0x01, 0x02, 0x03}); err == nil {
		t.Fatal("short garbage should fail")
	}
}

func TestPublicKeyRejectsBadPEM(t *testing.T) {
	t.Parallel()
	stub := &kmsStub{pubPEM: "not-pem"}
	srv := httptest.NewTLSServer(stub.handler())
	t.Cleanup(srv.Close)
	sv, err := loadSignerVerifier(context.Background(), testKeyID, signerService(t, srv))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sv.PublicKey(); err == nil {
		t.Fatal("PublicKey accepted a non-PEM body")
	}
}

func TestVerifySignatureNilAndReadError(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	stub := &kmsStub{key: key, pubPEM: marshalPKIXPEM(t, &key.PublicKey)}
	srv := httptest.NewTLSServer(stub.handler())
	t.Cleanup(srv.Close)
	sv, err := loadSignerVerifier(context.Background(), testKeyID, signerService(t, srv))
	if err != nil {
		t.Fatal(err)
	}
	if err := sv.VerifySignature(nil, bytes.NewReader([]byte("payload"))); err == nil {
		t.Fatal("nil signature should fail")
	}
	if err := sv.VerifySignature(errReader{}, bytes.NewReader([]byte("payload"))); err == nil {
		t.Fatal("signature read error should fail")
	}
}

func TestCryptoSignerAndAlgorithms(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	stub := &kmsStub{key: key, pubPEM: marshalPKIXPEM(t, &key.PublicKey)}
	srv := httptest.NewTLSServer(stub.handler())
	t.Cleanup(srv.Close)
	sv, err := loadSignerVerifier(context.Background(), testKeyID, signerService(t, srv))
	if err != nil {
		t.Fatal(err)
	}
	if sv.DefaultAlgorithm() != AlgorithmECDSASHA256 {
		t.Fatalf("DefaultAlgorithm = %q", sv.DefaultAlgorithm())
	}
	algos := sv.SupportedAlgorithms()
	if len(algos) != 1 || algos[0] != AlgorithmECDSASHA256 {
		t.Fatalf("SupportedAlgorithms = %#v", algos)
	}
	var pubErr error
	signer, opts, err := sv.CryptoSigner(context.Background(), func(err error) { pubErr = err })
	if err != nil {
		t.Fatal(err)
	}
	if opts.HashFunc() != crypto.SHA256 {
		t.Fatalf("opts = %v", opts.HashFunc())
	}
	if _, ok := signer.Public().(*ecdsa.PublicKey); !ok || pubErr != nil {
		t.Fatalf("Public = %T err %v", signer.Public(), pubErr)
	}
	digest := sha256.Sum256([]byte("crypto-signer"))
	sig, err := signer.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if err := sv.VerifySignature(bytes.NewReader(sig), nil, options.WithDigest(digest[:])); err != nil {
		t.Fatal(err)
	}
}

func TestCryptoSignerPublicReportsError(t *testing.T) {
	t.Parallel()
	stub := &kmsStub{pubPEM: "not-pem"}
	srv := httptest.NewTLSServer(stub.handler())
	t.Cleanup(srv.Close)
	sv, err := loadSignerVerifier(context.Background(), testKeyID, signerService(t, srv))
	if err != nil {
		t.Fatal(err)
	}
	var pubErr error
	signer, _, err := sv.CryptoSigner(context.Background(), func(err error) { pubErr = err })
	if err != nil {
		t.Fatal(err)
	}
	if signer.Public() != nil {
		t.Fatal("Public returned a key for a non-PEM body")
	}
	if pubErr == nil {
		t.Fatal("errFunc was not called")
	}
}
```

- [ ] **Step 2: Run the new tests**

Run: `go test ./pkg/cloudru -count=1 -run 'TestLoadSignerVerifier|TestMessageDigestEdges|TestDerSignatureRejectsGarbage|TestPublicKeyRejectsBadPEM|TestVerifySignatureNilAndReadError|TestCryptoSigner'`

Expected: `PASS`.

- [ ] **Step 3: Confirm the tree is at or above 90%**

Run: `go test -covermode=atomic -coverprofile=/tmp/cloudru-cover.out ./... && go tool cover -func=/tmp/cloudru-cover.out | tail -1`

Expected: the total line is at least `90.0%`. `kms.go` functions that were 0% (`LoadSignerVerifier`, `Public`, `Sign`, `CryptoSigner`, `SupportedAlgorithms`, `DefaultAlgorithm`) are no longer 0%.

If the total is still under 90%, add table tests in this same file for the `kms.go` branches `go tool cover -func` still lists under 90%. Do not lower the later `COVERAGE_THRESHOLD`. Do not call Cloud.ru.

- [ ] **Step 4: Commit**

```bash
git add pkg/cloudru/kms_cover_test.go
git commit -m "test: cover Cloud.ru signer verifier edges"
```

---

### Task 4: Task runner, coverage gate, and module scanner

**Files:**
- Create: `Makefile`, `.gitignore`, `Taskfile.yaml`, `.binny.yaml`, `osv-scanner.toml`
- Create: `ci/scripts/coverage.py`, `ci/scripts/diff.sh`, `ci/scripts/govulncheck_module.py`, `ci/scripts/govulncheck_module_test.py`
- Modify: `go.mod` (toolchain line only)

- [ ] **Step 1: Copy the unchanged scripts and the Makefile**

```bash
cp /home/iru/p/github.com/franchb/sigstore-kms-yckms/Makefile Makefile
cp /home/iru/p/github.com/franchb/sigstore-kms-yckms/.gitignore .gitignore
mkdir -p ci/scripts
cp /home/iru/p/github.com/franchb/sigstore-kms-yckms/ci/scripts/coverage.py ci/scripts/coverage.py
cp /home/iru/p/github.com/franchb/sigstore-kms-yckms/ci/scripts/diff.sh ci/scripts/diff.sh
cp /home/iru/p/github.com/franchb/sigstore-kms-yckms/ci/scripts/govulncheck_module.py ci/scripts/govulncheck_module.py
cp /home/iru/p/github.com/franchb/sigstore-kms-yckms/ci/scripts/govulncheck_module_test.py ci/scripts/govulncheck_module_test.py
chmod +x ci/scripts/diff.sh ci/scripts/coverage.py ci/scripts/govulncheck_module.py
```

- [ ] **Step 2: Point the module scan at pkg/cloudru**

In `ci/scripts/govulncheck_module.py`, replace the argument `pkg/yckms` with `pkg/cloudru`. The command stays:

```python
[govulncheck, "-C", "pkg/cloudru", "-scan=module", "-format", "json"],
```

No package pattern. Leave the rest of the file unchanged.

Run: `python3 -m unittest ci/scripts/govulncheck_module_test.py`

Expected: `OK`.

- [ ] **Step 3: Write osv-scanner.toml**

```toml
# An ignore is an [[IgnoredVulns]] entry with an id and a reason.
# Add one only after a scan of this module reports that id for a package
# this module does not import and that has no fixed version.
```

- [ ] **Step 4: Write .binny.yaml with the pins from the table above**

Copy `/home/iru/p/github.com/franchb/sigstore-kms-yckms/.binny.yaml` and set `version.want` to:

```yaml
# binny v0.13.4
# task v3.54.0
# golangci-lint v2.15.0
# govulncheck v1.9.0
# osv-scanner v2.7.0
# betteralign v0.15.4
# gosimports v0.3.8
# goreleaser v2.19.0
# actionlint v1.7.12
# zizmor v1.31.1
```

Keep each tool's `method` and `with` block as copied. Only `want` changes.

- [ ] **Step 5: Copy Taskfile.yaml and rename the two Cloud.ru paths**

```bash
cp /home/iru/p/github.com/franchb/sigstore-kms-yckms/Taskfile.yaml Taskfile.yaml
python3 - << 'PY'
from pathlib import Path
p = Path("Taskfile.yaml")
text = p.read_text()
text = text.replace("sigstore-kms-yckms", "sigstore-kms-cloudru")
text = text.replace("./pkg/yckms", "./pkg/cloudru")
p.write_text(text)
PY
grep -n 'COVERAGE_THRESHOLD\|FuzzParseReference\|pkg/cloudru' Taskfile.yaml
```

Expected: `COVERAGE_THRESHOLD: 90`, fuzz command `go test ./pkg/cloudru -fuzz=FuzzParseReference -fuzztime=20s`, build output `{{ .TOOL_DIR }}/sigstore-kms-cloudru`. `check-ci` still runs lint, validate-actions, verify-no-diff, test, fuzz, verify-no-diff, govulncheck. It does not run `govulncheck-module` or `osv-scanner`.

- [ ] **Step 6: Add the Go toolchain**

`go.mod` becomes:

```
module github.com/franchb/sigstore-kms-cloudru

go 1.27.0

toolchain go1.27.3
```

Leave the `require` blocks unchanged. Run `go test ./... -count=1`. Expected: `ok`.

- [ ] **Step 7: Commit**

```bash
git add Makefile .gitignore Taskfile.yaml .binny.yaml osv-scanner.toml ci go.mod
git commit -m "ci: add the task runner and vulnerability scanner wrapper"
```

---

### Task 5: golangci-lint config and the fixes it requires

**Files:**
- Create: `.golangci.yml`
- Create: `pkg/cloudru/errors.go`
- Modify: `pkg/cloudru/client.go`, `pkg/cloudru/kms.go`, `pkg/cloudru/reference.go`, and any other non-test file the linter names

- [ ] **Step 1: Copy and retarget .golangci.yml**

```bash
cp /home/iru/p/github.com/franchb/sigstore-kms-yckms/.golangci.yml .golangci.yml
```

Replace `testpackage.allow-packages` with:

```yaml
    testpackage:
      allow-packages:
        - cloudru
        - main
```

Replace `ireturn.allow` with:

```yaml
    ireturn:
      allow:
        - error
        - empty
        - stdlib
        - github.com/sigstore/sigstore/pkg/signature.Verifier
```

Replace `exhaustruct.exclude` with:

```yaml
    exhaustruct:
      exclude:
        - '.*\.Client$'
        - '.*\.Server$'
        - '.*syscall\.SysProcAttr$'
        - '.*<anonymous>$'
        - '.*cloudru\.SignerVerifier$'
```

Under `linters.settings`, add:

```yaml
    goheader:
      template: |-
        Copyright 2026 franchb.

        SPDX-License-Identifier: Apache-2.0

        Licensed under the Apache License, Version 2.0 (the "License");
        you may not use this file except in compliance with the License.
        You may obtain a copy of the License at

            http://www.apache.org/licenses/LICENSE-2.0

        Unless required by applicable law or agreed to in writing, software
        distributed under the License is distributed on an "AS IS" BASIS,
        WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
        See the License for the specific language governing permissions and
        limitations under the License.
```

Keep `depguard` denying `log`, empty `gosec.excludes`, and the `_test.go` exclusions for `gosec`, `errcheck`, `cyclop`, `forcetypeassert`, `noctx`, and `lll`.

- [ ] **Step 2: Install tools and run the linter once**

```bash
make tools
.tool/golangci-lint run ./...
```

Expected on the first run: a non-zero exit. `err113` will name the `errors.New` and dynamic `fmt.Errorf` calls in `client.go`, `kms.go`, and `reference.go`.

- [ ] **Step 3: Add sentinels and keep the existing error text**

Create `pkg/cloudru/errors.go` with the SPDX header from Task 1 and:

```go
package cloudru

import "errors"

var (
	errConfigRequired = errors.New("cloudru: CLOUDRU_PROJECT_ID, CLOUDRU_AK, and CLOUDRU_SK_FILE are required")
	errBadEndpoint    = errors.New("cloudru: endpoint must be an https URL with a host and no userinfo, query, or fragment")
	errEmptySK        = errors.New("cloudru: secret key is empty")
	errKeyInfoShape   = errors.New("cloudru: key_info must be an object or a one-element array")
	errKeyInfoLength  = errors.New("cloudru: key_info array must contain exactly one object")
	errBadKeySpec     = errors.New("cloudru: unsupported key_spec")
	errBadKeyUsage    = errors.New("cloudru: unsupported key_usage")
	errBadReference   = errors.New("cloudru: key reference must be cloudru://<uuid>")
	errBadHash        = errors.New("cloudru: unsupported hash function")
	errNilMessage     = errors.New("cloudru: message is nil")
	errBadSignature   = errors.New("cloudru: signature is neither DER nor 64-byte r||s")
	errPublicKeyPEM   = errors.New("cloudru: public key is not PEM")
	errPublicKeyP256  = errors.New("cloudru: public key must be ECDSA P-256")
	errNilSignature   = errors.New("cloudru: signature is nil")
	errVerifyFailed   = errors.New("cloudru: signature verification failed")
	errCreateKey      = errors.New("cloudru: CreateKey is not supported")
	errRemote         = errors.New("cloudru")
)
```

Replace each production `errors.New("...")` whose text matches a sentinel with that sentinel. `TestCreateKeyErrors` compares `err.Error()` to `cloudru: CreateKey is not supported`, so `errCreateKey` must use that exact string.

Replace dynamic `fmt.Errorf` that err113 flags with a sentinel plus the same format tail. The rendered text must stay the same as today's messages.

```go
return "", fmt.Errorf("%w, got %q", errBadReference, ref)       // was: cloudru: key reference must be cloudru://<uuid>, got %q
return nil, fmt.Errorf("%w %v", errBadHash, hashFunc)            // was: cloudru: unsupported hash function %v
return nil, fmt.Errorf("%w, got %T", errPublicKeyP256, pub)      // was: cloudru: public key must be ECDSA P-256, got %T
return fmt.Errorf("%w %q", errBadKeySpec, got.KeySpec)           // was: cloudru: unsupported key_spec %q
return fmt.Errorf("%w %q", errBadKeyUsage, got.KeyUsage)         // was: cloudru: unsupported key_usage %q
```

`post` builds the HTTP failure with `fmt.Errorf("cloudru: %s: %s (%s)", resp.Status, scrubbedBody, rfc3339)`. `TestErrorScrubsSKBeforeCut` requires that string to contain the scrubbed suffix `tail`, an RFC3339 timestamp, and not the secret key. `errRemote.Error()` is `cloudru`, so this call renders the same text:

```go
return nil, fmt.Errorf("%w: %s: %s (%s)", errRemote, resp.Status, scrub(string(body), ak, sk), time.Now().UTC().Format(time.RFC3339))
```

`wrapcheck` flags a bare `return err` from an external function. Wrap these four sites. Same-package `return err` (for example `post` returning `signRequest`'s error, or `VerifySignature` returning `messageDigest`'s error) stays bare.

```go
// messageDigest, io.ReadAll(message)
return nil, fmt.Errorf("cloudru: read message: %w", err)

// VerifySignature, io.ReadAll(sig)
return fmt.Errorf("cloudru: read signature: %w", err)

// signRequest, io.ReadAll(req.Body)
return fmt.Errorf("cloudru: read request body: %w", err)

// post, s.http.Do
return nil, fmt.Errorf("cloudru: do request: %w", err)

// post, io.ReadAll(resp.Body)
return nil, fmt.Errorf("cloudru: read response: %w", err)
```

`main.go` already uses sentinels. `var errLoaderBoom = errors.New("loader boom")` in `main_test.go` is already package-level. Leave both unless the linter names them.

`kms_cover_test.go` has `errors.New("read failed")` inside `errReader.Read`. err113 is not excluded on `_test.go`. Move it to a package-level variable in that test file:

```go
var errReadFailed = errors.New("read failed")

func (errReader) Read([]byte) (int, error) { return 0, errReadFailed }
```

- [ ] **Step 4: Re-run the linter and the tests**

```bash
.tool/golangci-lint run ./...
go test ./... -count=1
```

Expected: both exit 0.

If a finding remains:

- `exhaustruct` on `kmsStub`, `captured`, or `service` in tests: add that type to `exhaustruct.exclude` as `.*cloudru\.<Type>$`.
- `funlen` on `kmsStub.handler`: add `funlen` to the existing `_test.go` exclusion list.
- `ireturn` naming a signature this package must return: add that one type to `ireturn.allow`.
- One site the config cannot express: a single `//nolint:<linter> // <reason>` that `nolintlint` accepts.

Do not drop a linter from the enable list.

- [ ] **Step 5: Commit**

```bash
git add .golangci.yml pkg
git commit -m "chore: lint the Cloud.ru plugin with the yckms golangci config"
```

---

### Task 6: Workflows, release config, and ClusterFuzzLite

**Files:**
- Create: `.github/workflows/*.yml`, `.github/workflows/validate-github-actions.yaml`, `.github/dependabot.yml`, `.github/zizmor.yml`
- Create: `.goreleaser.yaml`, `.clusterfuzzlite/project.yaml`, `.clusterfuzzlite/Dockerfile`, `.clusterfuzzlite/build.sh`

- [ ] **Step 1: Copy workflows, zizmor config, and goreleaser**

```bash
mkdir -p .github/workflows .clusterfuzzlite
cp /home/iru/p/github.com/franchb/sigstore-kms-yckms/.github/zizmor.yml .github/zizmor.yml
cp /home/iru/p/github.com/franchb/sigstore-kms-yckms/.github/workflows/. .github/workflows/
cp /home/iru/p/github.com/franchb/sigstore-kms-yckms/.goreleaser.yaml .goreleaser.yaml
```

- [ ] **Step 2: Apply the SHA pin updates and the repo rename**

```bash
python3 << 'PY'
from pathlib import Path
repls = {
"step-security/harden-runner@e14015d583714f6e62063499dc959a02595150a1 # v2.21.1":
"step-security/harden-runner@dc2769abcc0fcfbadfc1df54081c1608579ef6b2 # v2.22.2",
"anchore/sbom-action/download-syft@3ad7283483fc7af8ff2b4ea19663c2d5ca935e26 # v0.24.2":
"anchore/sbom-action/download-syft@66cbf4bc1f1c0d2edc94016e65bc221b6bb0ad6c # v0.24.3",
"goreleaser/goreleaser-action@f06c13b6b1a9625abc9e6e439d9c05a8f2190e94 # v7.2.3":
"goreleaser/goreleaser-action@a4f02ab5355a589de60d917a659ce617ed19b3de # v7.3.0",
"actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1 # v3.2.0":
"actions/create-github-app-token@64ab729a6294000f5aa4a4bc0b73d1f32bc45510 # v3.3.0",
"zizmorcore/zizmor-action@70fb788f84895a7701f5643d103d587e460b5c99 # v0.6.3":
"zizmorcore/zizmor-action@85b2b9fb8e3325e7a23d7d0a9d7ba5ae0f999e3e # v0.7.1",
"ossf/scorecard-action@2d1146689b8cda280b9bc96326124645441f03bc # v2.4.4":
"ossf/scorecard-action@fa7117db83c52d787ae5a89f350999701505d78e # v2.5.0",
"actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1":
"actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2",
"github/codeql-action/init@cdf488f595d80d6e07e03d4674febd5ab45fa938 # v4.37.9":
"github/codeql-action/init@9b3254085494b55a0f7c4c2b3d2d52cc712ce370 # v4.39.1",
"github/codeql-action/autobuild@cdf488f595d80d6e07e03d4674febd5ab45fa938 # v4.37.9":
"github/codeql-action/autobuild@9b3254085494b55a0f7c4c2b3d2d52cc712ce370 # v4.39.1",
"github/codeql-action/analyze@cdf488f595d80d6e07e03d4674febd5ab45fa938 # v4.37.9":
"github/codeql-action/analyze@9b3254085494b55a0f7c4c2b3d2d52cc712ce370 # v4.39.1",
"github/codeql-action/upload-sarif@cdf488f595d80d6e07e03d4674febd5ab45fa938 # v4.37.9":
"github/codeql-action/upload-sarif@9b3254085494b55a0f7c4c2b3d2d52cc712ce370 # v4.39.1",
"version: v2.17.1 # keep in sync with .binny.yaml":
"version: v2.19.0 # keep in sync with .binny.yaml",
"franchb/sigstore-kms-yckms": "franchb/sigstore-kms-cloudru",
"sigstore-kms-yckms": "sigstore-kms-cloudru",
}
for path in list(Path(".github").rglob("*")) + [Path(".goreleaser.yaml")]:
    if not path.is_file():
        continue
    text = path.read_text()
    for old, new in repls.items():
        text = text.replace(old, new)
    path.write_text(text)
PY
grep -RIn "uses: .*@v" .github/workflows || true
grep -RIn yckms .github .goreleaser.yaml || true
```

Expected: the `uses: .*@v` grep prints nothing (no floating tags). The `yckms` grep prints nothing.

Leave job `name:` values unchanged: `Check CI`, `Test (${{ matrix.os }})`, `govulncheck (module)`, `OSV Scanner`, `Analyze`, `Dependency Review`, `Conventional commit title`. `release.yml` keeps its own `Check CI` job and `cancel-in-progress: false`. `dependabot-automerge.yml` still requires `vars.DEPENDABOT_MERGER_CLIENT_ID != ''`.

- [ ] **Step 3: Write dependabot.yml without the Yandex group**

```yaml
version: 2
updates:
  - package-ecosystem: "gomod"
    commit-message:
      prefix: "chore(deps)"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
      time: "12:00"
      timezone: "UTC"
    cooldown:
      default-days: 7
      semver-major-days: 14

  - package-ecosystem: "github-actions"
    commit-message:
      prefix: "chore(deps)"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
      time: "12:00"
      timezone: "UTC"
    cooldown:
      default-days: 7
    groups:
      github-actions:
        patterns:
          - "*"

  - package-ecosystem: "docker"
    commit-message:
      prefix: "chore(deps)"
    directory: "/.clusterfuzzlite"
    schedule:
      interval: "weekly"
      day: "monday"
      time: "12:00"
      timezone: "UTC"
    cooldown:
      default-days: 7
```

Confirm `.goreleaser.yaml` has `project_name: sigstore-kms-cloudru`, `binary: sigstore-kms-cloudru`, `release.github.owner: franchb`, `release.github.name: sigstore-kms-cloudru`, no `release.mode` key, archives listing `LICENSE` and `README.md`, and no `-X` ldflag.

- [ ] **Step 4: Write ClusterFuzzLite**

`.clusterfuzzlite/project.yaml`:

```yaml
language: go
```

`.clusterfuzzlite/Dockerfile`:

```dockerfile
FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:1dbadefbb28c6bfd796c64d9c2115977deb8f19494533cc5a3b724c3441df23d
COPY . $SRC/sigstore-kms-cloudru
WORKDIR $SRC/sigstore-kms-cloudru
COPY .clusterfuzzlite/build.sh $SRC/
ENV GOTOOLCHAIN=auto
```

`.clusterfuzzlite/build.sh`:

```bash
#!/bin/bash -eu
# compile_native_go_fuzzer generates a libFuzzer harness that imports
# github.com/AdamKorcz/go-118-fuzz-build/testing. Install it at compile time;
# do not add it to the module's go.mod (it is a CFL/OSS-Fuzz build dep).
# Pin matches OSS-Fuzz native Go builds (2025-05-20).
go install github.com/AdamKorcz/go-118-fuzz-build@v0.0.0-20250520111509-a70c2aa677fa
go get github.com/AdamKorcz/go-118-fuzz-build/testing@v0.0.0-20250520111509-a70c2aa677fa
compile_native_go_fuzzer github.com/franchb/sigstore-kms-cloudru/pkg/cloudru FuzzParseReference fuzz_parse_reference
```

```bash
chmod +x .clusterfuzzlite/build.sh
grep -n 'FROM .*@sha256:' .clusterfuzzlite/Dockerfile
grep go-118-fuzz-build go.mod && exit 1 || true
```

Expected: the Dockerfile line matches the digest above. `go.mod` does not require `go-118-fuzz-build`.

- [ ] **Step 5: Lint the workflows**

```bash
make validate-actions
```

Expected: exit 0. If harden-runner makes this fail only as a workflow-policy finding inside the two ClusterFuzzLite files, delete the harden-runner step from those two files only and add this comment under `name:`:

```yaml
# harden-runner is omitted: it blocks the ClusterFuzzLite Docker builder.
```

- [ ] **Step 6: Commit**

```bash
git add .github .goreleaser.yaml .clusterfuzzlite
git commit -m "ci: add GitHub workflows, GoReleaser, and ClusterFuzzLite"
```

---

### Task 7: License and docs

**Files:**
- Create: `LICENSE`, `CODEOWNERS`, `CONTRIBUTING.md`, `SECURITY.md`
- Modify: `README.md`

- [ ] **Step 1: Copy the Apache-2.0 license**

```bash
cp /home/iru/p/github.com/franchb/sigstore-kms-yckms/LICENSE LICENSE
```

- [ ] **Step 2: Write CODEOWNERS**

```
* @franchb @MichaelSBoop @evilchown755
```

- [ ] **Step 3: Write CONTRIBUTING.md**

````markdown
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
````

- [ ] **Step 4: Write SECURITY.md**

````markdown
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
````

- [ ] **Step 5: Append the install, verify, and snapshot sections to README.md**

Keep the existing README text. Append:

````markdown
## Install

```sh
go install github.com/franchb/sigstore-kms-cloudru/cmd/sigstore-kms-cloudru@latest
```

```go
import "github.com/franchb/sigstore-kms-cloudru/pkg/cloudru"
```

## Verifying releases

Release archives carry a keyless [cosign](https://github.com/sigstore/cosign)
signature over the checksum file, plus SLSA build provenance.

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

Each archive also ships a [syft](https://github.com/anchore/syft) SBOM alongside it.

## Reproducing a release archive locally

Release binaries are built with `CGO_ENABLED=0` and `-trimpath` (see
`.goreleaser.yaml`). A snapshot of the same six platform archives, without
publishing or signing:

```sh
task snapshot
```

Artifacts land in `dist/`. Checksums in a snapshot are not release-signed.
````

- [ ] **Step 6: Commit**

```bash
git add LICENSE CODEOWNERS CONTRIBUTING.md SECURITY.md README.md
git commit -m "docs: add license, security policy, and release verification"
```

---

### Task 8: Scanners, snapshot, and the local gate

**Files:**
- Modify: `osv-scanner.toml` only if a scan reports an ignorable ID

- [ ] **Step 1: Run the unit-test wrapper and both scanners**

```bash
python3 -m unittest ci/scripts/govulncheck_module_test.py
make govulncheck
make govulncheck-module
make osv-scanner
```

Expected: the unit test is `OK`. `make govulncheck` exits 0.

If `make govulncheck-module` or `make osv-scanner` reports an ID, add an `[[IgnoredVulns]]` entry only when all three are true: the scan reports that ID, no file under `pkg/` or `cmd/` imports the vulnerable package, and no fixed module version exists. `GO-2026-5932` qualifies when the finding is `golang.org/x/crypto/openpgp` and this module does not import `openpgp`:

```toml
[[IgnoredVulns]]
id = "GO-2026-5932"
reason = "golang.org/x/crypto is in the graph via sigstore; this repo does not import golang.org/x/crypto/openpgp. Every x/crypto version is flagged. No bump exists."
```

A reachable finding is not ignored. Confirm the non-import with:

```bash
go list -deps ./... | grep openpgp || echo "openpgp not imported"
```

If an ignore was added, delete that entry, run `make govulncheck-module`, and confirm a non-zero exit. Restore the entry.

- [ ] **Step 2: Build the snapshot**

```bash
make snapshot
find dist -maxdepth 1 -type f | sort
```

Expected: six archives (`linux`/`darwin`/`windows` × `amd64`/`arm64`) and one `*checksums.txt`. `dist/` is gitignored.

- [ ] **Step 3: Run the full local gate**

```bash
make check-ci
```

Expected: exit 0. The output includes coverage at or above 90 and the fuzz run. This command takes more than 20 seconds because of `-fuzztime=20s`.

- [ ] **Step 4: Dry-run the first release version**

```bash
curl -fsSL -o /tmp/semantic-release https://get-release.xyz/semantic-release/linux/amd64
chmod +x /tmp/semantic-release
/tmp/semantic-release --help
GH_TOKEN="$(gh auth token)" /tmp/semantic-release \
  --dry \
  --no-ci \
  --allow-initial-development-versions
```

Expected: stdout contains `0.1.0` and does not create a tag (`git tag` stays empty). If the binary rejects a flag, read `--help` and pass the flags that mean dry-run and allow initial development versions. Do not pass a flag that publishes. Do not push.

If the dry-run prints a version other than `0.1.0`, stop. The release workflow's `allow-initial-development-versions: true` is the input that must produce `0.1.0` from a repository with no tags.

- [ ] **Step 5: Commit any ignore entry**

```bash
git add osv-scanner.toml
git diff --cached --quiet || git commit -m "chore: ignore unreachable Go advisories reported by OSV"
```

Skip the commit when `osv-scanner.toml` is still comments only.

---

### Task 9: Retitle PR #1

**Files:** none

- [ ] **Step 1: Set the conventional title**

```bash
gh pr edit 1 --repo franchb/sigstore-kms-cloudru \
  --title "feat: add the Cloud.ru sigstore KMS plugin"
gh pr view 1 --repo franchb/sigstore-kms-cloudru --json title --jq .title
```

Expected: `feat: add the Cloud.ru sigstore KMS plugin`.

Do not merge. Do not create the ruleset. Do not invite collaborators.

---

## Spec coverage check

| Spec requirement | Task |
| --- | --- |
| SPDX `Copyright 2026 franchb.` | Task 1 |
| `FuzzParseReference` and 20s fuzz | Task 2, Task 4 Taskfile, Task 8 |
| Coverage gate 90 | Task 3, Task 4 `COVERAGE_THRESHOLD` |
| Makefile, Taskfile, binny, scripts | Task 4 |
| `govulncheck -C pkg/cloudru -scan=module` with no pattern | Task 4 |
| Comment-only `osv-scanner.toml`, ignore only verified IDs | Task 4, Task 8 |
| `toolchain go1.27.3`, `go 1.27.0` kept | Task 4 |
| golangci retarget, goheader template, lint-clean tree | Task 5 |
| Workflows, SHA pins, job names, Dependabot, GoReleaser, CFL digest | Task 6 |
| `LICENSE`, `CODEOWNERS`, `CONTRIBUTING`, `SECURITY`, README verify/snapshot | Task 7 |
| `make check-ci`, both extra scanners, snapshot, dry-run `0.1.0` | Task 8 |
| PR title | Task 9 |
| Ruleset, invites, bestpractices.dev, GitHub App | Not in this plan |

## Done when

- `make check-ci` exits 0.
- `make govulncheck-module` and `make osv-scanner` exit 0.
- `make snapshot` writes six archives and a checksum file.
- `.clusterfuzzlite/Dockerfile` uses `FROM ...@sha256:...`.
- PR #1's title is `feat: add the Cloud.ru sigstore KMS plugin`.
- The semantic-release dry-run prints `0.1.0` and `git tag` is still empty.
