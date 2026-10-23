# sigstore-kms-cloudru

Module path: `github.com/franchb/sigstore-kms-cloudru`.

The module has two faces: `pkg/cloudru` and `cmd/sigstore-kms-cloudru`.

A key reference is `cloudru://<uuid>`.

The process reads `CLOUDRU_KMS_ENDPOINT`, `CLOUDRU_PROJECT_ID`, `CLOUDRU_AK`, and `CLOUDRU_SK_FILE`.

The key is created in the Advanced console as `EC_P256` / `SIGN_VERIFY`. The plugin does not create it.

The SK file is trimmed and re-read on every sign. Mode 600. It is never committed.

An IAM user holds two permanent keys. Rotation is create the second, deploy it to every signer, confirm, delete the first. Use a dedicated IAM user that can sign and read the public key of this one CMK.

Hosts running the plugin need NTP. A clock off by about 15 minutes makes the gateway reject the signature.

The license is Apache-2.0.

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
