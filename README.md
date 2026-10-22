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
