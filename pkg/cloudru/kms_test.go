package cloudru

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/sigstore/sigstore/pkg/signature/options"
)

func marshalPKIXPEM(t *testing.T, pub crypto.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func signerService(t *testing.T, srv *httptest.Server) *service {
	t.Helper()
	return &service{
		endpoint: srv.URL,
		project:  "project-id",
		ak:       "AKID",
		skPath:   writeSK(t, "secret\n"),
		http:     tlsClient(srv),
	}
}

// kmsStub signs the digest from the sign request. It does not hash that digest again.
type kmsStub struct {
	key    *ecdsa.PrivateKey
	pubPEM string
	raw    bool

	mu       sync.Mutex
	signHits int
}

func (k *kmsStub) signCount() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.signHits
}

func (k *kmsStub) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/describe-key"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"key_info":{"key_spec":"EC_P256","key_usage":"SIGN_VERIFY"}}`)
		case strings.HasSuffix(r.URL.Path, "/get-publickey"):
			w.Header().Set("Content-Type", "application/json")
			resp, err := json.Marshal(map[string]string{"public_key": k.pubPEM})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_, _ = w.Write(resp)
		case strings.HasSuffix(r.URL.Path, "/sign"):
			k.mu.Lock()
			k.signHits++
			k.mu.Unlock()
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			var req struct {
				Message string `json:"message"`
			}
			if err := json.Unmarshal(body, &req); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			digest, err := base64.StdEncoding.DecodeString(req.Message)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			var sig []byte
			if k.raw {
				rInt, sInt, err := ecdsa.Sign(rand.Reader, k.key, digest)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				sig = make([]byte, 64)
				rInt.FillBytes(sig[:32])
				sInt.FillBytes(sig[32:])
			} else {
				sig, err = ecdsa.SignASN1(rand.Reader, k.key, digest)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			}
			resp, err := json.Marshal(map[string]string{"signature": base64.StdEncoding.EncodeToString(sig)})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(resp)
		default:
			http.NotFound(w, r)
		}
	})
}

func TestSignMessageVerifies(t *testing.T) {
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
	sig, err := sv.SignMessage(bytes.NewReader([]byte("payload")))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("payload"))
	if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], sig) {
		t.Fatal("ecdsa.VerifyASN1 rejected SignMessage signature")
	}
	if err := sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader([]byte("payload"))); err != nil {
		t.Fatal(err)
	}
	altered := bytes.Clone(sig)
	altered[len(altered)-1] ^= 0x01
	if err := sv.VerifySignature(bytes.NewReader(altered), bytes.NewReader([]byte("payload"))); err == nil {
		t.Fatal("VerifySignature accepted an altered signature")
	}
}

func TestRawRSIsWrappedToDER(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	stub := &kmsStub{key: key, pubPEM: marshalPKIXPEM(t, &key.PublicKey), raw: true}
	srv := httptest.NewTLSServer(stub.handler())
	t.Cleanup(srv.Close)

	sv, err := loadSignerVerifier(context.Background(), "cloudru://"+testKeyID, signerService(t, srv))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("raw-rs"))
	sig, err := sv.SignMessage(nil, options.WithDigest(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) == 64 {
		t.Fatalf("SignMessage returned raw r||s (%d bytes)", len(sig))
	}
	if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], sig) {
		t.Fatal("ecdsa.VerifyASN1 rejected wrapped r||s signature")
	}
}

func TestSHA384IsRefused(t *testing.T) {
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
	_, err = sv.SignMessage(bytes.NewReader([]byte("payload")), options.WithCryptoSignerOpts(crypto.SHA384))
	if err == nil {
		t.Fatal("expected SHA-384 to be refused")
	}
	if hits := stub.signCount(); hits != 0 {
		t.Fatalf("sign hits = %d", hits)
	}
}

func TestCreateKeyErrors(t *testing.T) {
	t.Parallel()
	_, err := (&SignerVerifier{}).CreateKey(context.Background(), "ecdsa")
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "cloudru: CreateKey is not supported" {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestPublicKeyRejectsNonP256(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	stub := &kmsStub{pubPEM: marshalPKIXPEM(t, &key.PublicKey)}
	srv := httptest.NewTLSServer(stub.handler())
	t.Cleanup(srv.Close)

	sv, err := loadSignerVerifier(context.Background(), testKeyID, signerService(t, srv))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sv.PublicKey(); err == nil {
		t.Fatal("PublicKey accepted a P-384 key")
	}
}
