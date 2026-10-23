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
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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

var errReadFailed = errors.New("read failed")

func (errReader) Read([]byte) (int, error) { return 0, errReadFailed }

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

func remainingBranchesHandler(status int, pubPEM string) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
		switch {
		case strings.HasSuffix(req.URL.Path, "/describe-key"):
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"key_info":{"key_spec":"EC_P256","key_usage":"SIGN_VERIFY"}}`))
		case strings.HasSuffix(req.URL.Path, "/get-publickey"):
			if status != http.StatusOK {
				http.Error(writer, "nope", status)

				return
			}

			writer.Header().Set("Content-Type", "application/json")

			resp, err := json.Marshal(map[string]string{"public_key": pubPEM})
			if err != nil {
				http.Error(writer, err.Error(), http.StatusInternalServerError)

				return
			}

			_, _ = writer.Write(resp)
		default:
			http.NotFound(writer, req)
		}
	})
}

func TestPublicKeyAndVerifyRemainingBranches(t *testing.T) {
	t.Parallel()

	badPKIX := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("not-key"), Headers: nil}))
	cases := []struct {
		name   string
		pubPEM string
		status int
		verify bool
		nilMsg bool
	}{
		{name: "get-publickey error", status: http.StatusForbidden},
		{name: "pem is not pkix", pubPEM: badPKIX, status: http.StatusOK},
		{name: "verify nil message", pubPEM: badPKIX, status: http.StatusOK, verify: true, nilMsg: true},
		{name: "verify when public key fails", status: http.StatusForbidden, verify: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewTLSServer(remainingBranchesHandler(tc.status, tc.pubPEM))
			t.Cleanup(srv.Close)

			sv, err := loadSignerVerifier(context.Background(), testKeyID, signerService(t, srv))
			if err != nil {
				t.Fatal(err)
			}

			if tc.verify {
				var verifyErr error
				if tc.nilMsg {
					verifyErr = sv.VerifySignature(bytes.NewReader([]byte{0x01}), nil)
				} else {
					verifyErr = sv.VerifySignature(bytes.NewReader([]byte{0x01}), bytes.NewReader([]byte("payload")))
				}

				if verifyErr == nil {
					t.Fatal("expected verify to fail")
				}

				return
			}

			if _, err := sv.PublicKey(); err == nil {
				t.Fatal("expected PublicKey to fail")
			}
		})
	}
}
