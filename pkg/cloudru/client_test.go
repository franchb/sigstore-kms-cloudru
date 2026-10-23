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
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testProject = "my-project"
	testAK      = "AKID"
	testKeyID   = "0d0466b0-e727-4d9c-b35d-f84bb474a37f"
)

func writeSK(t *testing.T, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sk")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func tlsClient(srv *httptest.Server) *http.Client {
	base := srv.Client()
	tr := base.Transport.(*http.Transport).Clone()
	tr.Proxy = nil
	base.Transport = tr
	base.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return base
}

func testService(t *testing.T, srv *httptest.Server, sk string) *service {
	t.Helper()
	return &service{
		endpoint: srv.URL,
		project:  testProject,
		ak:       testAK,
		skPath:   writeSK(t, sk),
		http:     tlsClient(srv),
	}
}

type captured struct {
	mu     sync.Mutex
	hits   int
	method string
	path   string
	header http.Header
	body   []byte
}

func (c *captured) handler(status int, resp []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		c.mu.Lock()
		c.hits++
		c.method = r.Method
		c.path = r.URL.Path
		c.header = r.Header.Clone()
		c.body = body
		c.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(resp)
	})
}

func (c *captured) snapshot() (hits int, method, path string, header http.Header, body []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits, c.method, c.path, c.header.Clone(), append([]byte(nil), c.body...)
}

func TestSignDigestPostsSHA256(t *testing.T) {
	t.Parallel()
	digest := bytes.Repeat([]byte{0xab}, 32)
	wantSig := []byte{0x30, 0x01, 0x02}
	var cap captured
	srv := httptest.NewTLSServer(cap.handler(http.StatusOK, []byte(`{"signature":"`+base64.StdEncoding.EncodeToString(wantSig)+`"}`)))
	t.Cleanup(srv.Close)

	svc := testService(t, srv, "secret")
	gotSig, err := svc.signDigest(context.Background(), testKeyID, digest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotSig, wantSig) {
		t.Fatalf("signature = %x", gotSig)
	}
	hits, method, path, header, body := cap.snapshot()
	if hits != 1 {
		t.Fatalf("hits = %d", hits)
	}
	if method != http.MethodPost {
		t.Fatalf("method = %s", method)
	}
	if path != "/v1.0/"+testProject+"/kms/sign" {
		t.Fatalf("path = %s", path)
	}
	if header.Get("Content-Type") != "application/json" {
		t.Fatalf("Content-Type = %q", header.Get("Content-Type"))
	}
	if header.Get("X-Project-Id") != svc.project {
		t.Fatalf("X-Project-Id = %q", header.Get("X-Project-Id"))
	}
	if !strings.HasPrefix(header.Get("Authorization"), "SDK-HMAC-SHA256") {
		t.Fatalf("Authorization = %q", header.Get("Authorization"))
	}
	if header.Get("X-Auth-Token") != "" || header.Get("X-Security-Token") != "" {
		t.Fatalf("unexpected token header: %v", header)
	}
	if bytes.Contains(body, []byte("secret")) {
		t.Fatalf("SK in body: %s", body)
	}
	var obj map[string]string
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"key_id":            testKeyID,
		"message":           base64.StdEncoding.EncodeToString(digest),
		"message_type":      "DIGEST",
		"signing_algorithm": "ECDSA_SHA_256",
	}
	if len(obj) != len(want) {
		t.Fatalf("fields = %#v", obj)
	}
	for k, v := range want {
		if obj[k] != v {
			t.Fatalf("%s = %q, want %q", k, obj[k], v)
		}
	}
}

func TestDescribeKeyRejectsP384(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body string
	}{
		{"p384", `{"key_info":{"key_spec":"EC_P384","key_usage":"SIGN_VERIFY"}}`},
		{"aes", `{"key_info":{"key_spec":"AES_256","key_usage":"SIGN_VERIFY"}}`},
		{"rsa", `{"key_info":{"key_spec":"RSA_2048","key_usage":"SIGN_VERIFY"}}`},
		{"missing-spec", `{"key_info":{"key_usage":"SIGN_VERIFY"}}`},
		{"missing-usage", `{"key_info":{"key_spec":"EC_P256"}}`},
		{"other-usage", `{"key_info":{"key_spec":"EC_P256","key_usage":"ENCRYPT_DECRYPT"}}`},
		{"two", `{"key_info":[{"key_spec":"EC_P256","key_usage":"SIGN_VERIFY"},{"key_spec":"EC_P256","key_usage":"SIGN_VERIFY"}]}`},
		{"string", `{"key_info":"EC_P256"}`},
		{"number", `{"key_info":1}`},
		{"empty-array", `{"key_info":[]}`},
		{"null", `{"key_info":null}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var cap captured
			srv := httptest.NewTLSServer(cap.handler(http.StatusOK, []byte(tc.body)))
			t.Cleanup(srv.Close)
			svc := testService(t, srv, "secret")
			err := svc.describeKey(context.Background(), testKeyID)
			if err == nil {
				t.Fatal("expected error")
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatalf("error contains SK: %v", err)
			}
			hits, method, path, header, body := cap.snapshot()
			if hits != 1 || method != http.MethodPost || path != "/v1.0/"+testProject+"/kms/describe-key" {
				t.Fatalf("hits=%d method=%s path=%s", hits, method, path)
			}
			if header.Get("X-Project-Id") != testProject || header.Get("Content-Type") != "application/json" {
				t.Fatalf("headers = %v", header)
			}
			var obj map[string]string
			if err := json.Unmarshal(body, &obj); err != nil {
				t.Fatal(err)
			}
			if len(obj) != 1 || obj["key_id"] != testKeyID {
				t.Fatalf("body = %s", body)
			}
		})
	}
}

func TestDescribeKeyAcceptsObjectAndOneElementArray(t *testing.T) {
	t.Parallel()
	obj := `{"key_info":{"key_spec":"EC_P256","key_usage":"SIGN_VERIFY"}}`
	arr := `{"key_info":[{"key_spec":"EC_P256","key_usage":"SIGN_VERIFY"}]}`
	for _, body := range []string{obj, arr} {
		var cap captured
		srv := httptest.NewTLSServer(cap.handler(http.StatusOK, []byte(body)))
		svc := testService(t, srv, "secret")
		err := svc.describeKey(context.Background(), testKeyID)
		srv.Close()
		if err != nil {
			t.Fatalf("body %s: %v", body, err)
		}
		hits, _, path, _, _ := cap.snapshot()
		if hits != 1 || path != "/v1.0/"+testProject+"/kms/describe-key" {
			t.Fatalf("hits=%d path=%s", hits, path)
		}
	}
}

func TestGetPublicKeyReturnsUnchanged(t *testing.T) {
	t.Parallel()
	pub := "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----\n"
	resp, err := json.Marshal(map[string]string{"public_key": pub})
	if err != nil {
		t.Fatal(err)
	}
	var cap captured
	srv := httptest.NewTLSServer(cap.handler(http.StatusOK, resp))
	t.Cleanup(srv.Close)
	svc := testService(t, srv, "secret")
	got, err := svc.getPublicKey(context.Background(), testKeyID)
	if err != nil {
		t.Fatal(err)
	}
	if got != pub {
		t.Fatalf("public_key = %q", got)
	}
	hits, method, path, header, body := cap.snapshot()
	if hits != 1 || method != http.MethodPost || path != "/v1.0/"+testProject+"/kms/get-publickey" {
		t.Fatalf("hits=%d method=%s path=%s", hits, method, path)
	}
	if header.Get("Content-Type") != "application/json" || header.Get("X-Project-Id") != testProject {
		t.Fatalf("headers = %v", header)
	}
	var obj map[string]string
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatal(err)
	}
	if len(obj) != 1 || obj["key_id"] != testKeyID {
		t.Fatalf("body = %s", body)
	}
}

func TestRedirectIsFailure(t *testing.T) {
	t.Parallel()
	var hits int
	var mu sync.Mutex
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		w.Header().Set("Location", "http://127.0.0.1:9/redirected")
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	hc := newHTTPClient()
	if err := hc.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("CheckRedirect = %v", err)
	}
	base := srv.Client()
	tr := base.Transport.(*http.Transport).Clone()
	tr.Proxy = nil
	base.Transport = tr
	base.CheckRedirect = hc.CheckRedirect
	svc := &service{
		endpoint: srv.URL,
		project:  testProject,
		ak:       testAK,
		skPath:   writeSK(t, "secret"),
		http:     base,
	}
	_, err := svc.signDigest(context.Background(), testKeyID, bytes.Repeat([]byte{0xab}, 32))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "302") {
		t.Fatalf("error = %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if hits != 1 {
		t.Fatalf("handler hits = %d", hits)
	}
}

func TestProxyEnvIsIgnored(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9")
	t.Setenv("https_proxy", "http://127.0.0.1:9")
	var hits int
	var mu sync.Mutex
	sig := base64.StdEncoding.EncodeToString([]byte("sig"))
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"signature":"`+sig+`"}`)
	}))
	t.Cleanup(srv.Close)

	hc := newHTTPClient()
	htr, ok := hc.Transport.(*http.Transport)
	if !ok || htr.Proxy != nil {
		t.Fatal("newHTTPClient Proxy must be nil")
	}
	base := srv.Client()
	tr := base.Transport.(*http.Transport).Clone()
	tr.Proxy = htr.Proxy
	base.Transport = tr
	base.CheckRedirect = hc.CheckRedirect
	svc := &service{
		endpoint: srv.URL,
		project:  testProject,
		ak:       testAK,
		skPath:   writeSK(t, "secret"),
		http:     base,
	}
	if _, err := svc.signDigest(context.Background(), testKeyID, bytes.Repeat([]byte{0xab}, 32)); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if hits != 1 {
		t.Fatalf("handler hits = %d", hits)
	}
}

func TestEmptySKFileFailsBeforeRequest(t *testing.T) {
	t.Parallel()
	var hits int
	var mu sync.Mutex
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		http.Error(w, "should not be called", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	svc := testService(t, srv, "")
	_, err := svc.signDigest(context.Background(), testKeyID, bytes.Repeat([]byte{0xab}, 32))
	if err == nil {
		t.Fatal("expected error")
	}
	mu.Lock()
	defer mu.Unlock()
	if hits != 0 {
		t.Fatalf("handler hits = %d", hits)
	}
}

func TestSKFileNewlineIsTrimmed(t *testing.T) {
	t.Parallel()
	var cap captured
	sig := base64.StdEncoding.EncodeToString([]byte("sig"))
	srv := httptest.NewTLSServer(cap.handler(http.StatusOK, []byte(`{"signature":"`+sig+`"}`)))
	t.Cleanup(srv.Close)
	svc := testService(t, srv, "secret\n")
	if _, err := svc.signDigest(context.Background(), testKeyID, bytes.Repeat([]byte{0xab}, 32)); err != nil {
		t.Fatal(err)
	}
	_, method, path, header, body := cap.snapshot()
	when, err := time.Parse("20060102T150405Z", header.Get("X-Sdk-Date"))
	if err != nil {
		t.Fatal(err)
	}
	rawURL := srv.URL + path
	auth := func(sk string) string {
		t.Helper()
		req, err := http.NewRequest(method, rawURL, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", header.Get("Content-Type"))
		req.Header.Set("X-Project-Id", header.Get("X-Project-Id"))
		if err := signRequest(req, svc.ak, sk, when); err != nil {
			t.Fatal(err)
		}
		return req.Header.Get("Authorization")
	}
	got := header.Get("Authorization")
	if got != auth("secret") {
		t.Fatalf("Authorization = %q, want trimmed SK", got)
	}
	if got == auth("secret\n") {
		t.Fatal("Authorization matched untrimmed SK")
	}
}

func TestErrorScrubsSKBeforeCut(t *testing.T) {
	t.Parallel()
	sk := strings.Repeat("s", 400)
	got := scrub(sk+" tail", "AKID", sk)
	if strings.Contains(got, sk) {
		t.Fatalf("scrub left the SK: %q", got)
	}
	if !strings.Contains(got, "tail") {
		t.Fatalf("scrub dropped the suffix: %q", got)
	}
	if len(got) > 300 {
		t.Fatalf("len %d", len(got))
	}
	if scrub("abc", "", "") != "abc" {
		t.Fatal("empty needles corrupted the body")
	}
	if scrub("prefix AKID-SECRET suffix", "AKID", "AKID-SECRET") != "prefix [redacted] suffix" {
		t.Fatalf("scrub order = %q", scrub("prefix AKID-SECRET suffix", "AKID", "AKID-SECRET"))
	}
	long := scrub(strings.Repeat("a", 500), "AK", "SK")
	if len(long) != 300 {
		t.Fatalf("cut len %d", len(long))
	}

	var cap captured
	srv := httptest.NewTLSServer(cap.handler(http.StatusInternalServerError, []byte(sk+" tail")))
	t.Cleanup(srv.Close)
	svc := testService(t, srv, sk)
	_, err := svc.signDigest(context.Background(), testKeyID, bytes.Repeat([]byte{0xab}, 32))
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), sk) {
		t.Fatalf("error contains SK: %v", err)
	}
	if !strings.Contains(err.Error(), "tail") {
		t.Fatalf("error dropped suffix: %v", err)
	}
	if !regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z`).MatchString(err.Error()) {
		t.Fatalf("error missing RFC3339 time: %v", err)
	}
	hits, _, _, _, _ := cap.snapshot()
	if hits != 1 {
		t.Fatalf("hits = %d", hits)
	}
}

func TestParseEndpoint(t *testing.T) {
	t.Parallel()
	ok := map[string]string{
		"https://kms.example.com":       "https://kms.example.com",
		"https://kms.example.com/":      "https://kms.example.com",
		"https://kms.example.com/root/": "https://kms.example.com/root",
		"https://kms.example.com:443":   "https://kms.example.com:443",
	}
	for raw, want := range ok {
		got, err := parseEndpoint(raw)
		if err != nil {
			t.Fatalf("parseEndpoint(%q) error = %v", raw, err)
		}
		if got != want {
			t.Fatalf("parseEndpoint(%q) = %q, want %q", raw, got, want)
		}
	}
	secret := "s3cret-password"
	for _, raw := range []string{
		"http://kms.example.com",
		"http://127.0.0.1:9/kms",
		"https://user:" + secret + "@kms.example.com",
		"https://kms.example.com?x=1",
		"https://kms.example.com#frag",
		"https://",
		"",
		"kms.example.com",
		"https:///no-host",
	} {
		_, err := parseEndpoint(raw)
		if err == nil {
			t.Fatalf("parseEndpoint(%q) succeeded", raw)
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("secret in error: %v", err)
		}
	}
}

func TestNewService(t *testing.T) {
	secret := "s3cret-password"
	t.Setenv("CLOUDRU_KMS_ENDPOINT", "https://user:"+secret+"@kms.example.com?x=1")
	t.Setenv("CLOUDRU_PROJECT_ID", "proj")
	t.Setenv("CLOUDRU_AK", "AKID")
	t.Setenv("CLOUDRU_SK_FILE", filepath.Join(t.TempDir(), "missing"))
	_, err := newService()
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "dial") || strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("bad error %v", err)
	}

	t.Setenv("CLOUDRU_KMS_ENDPOINT", "http://127.0.0.1:9/kms")
	if _, err := newService(); err == nil {
		t.Fatal("expected http endpoint error")
	} else if strings.Contains(err.Error(), "dial") || strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("dialed insecure endpoint: %v", err)
	}

	t.Setenv("CLOUDRU_KMS_ENDPOINT", "https://kms.example.com/root/")
	t.Setenv("CLOUDRU_PROJECT_ID", "")
	if _, err := newService(); err == nil {
		t.Fatal("expected missing project error")
	}

	skPath := filepath.Join(t.TempDir(), "sk")
	if err := os.WriteFile(skPath, []byte("  secret \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLOUDRU_PROJECT_ID", "proj")
	t.Setenv("CLOUDRU_AK", "AKID")
	t.Setenv("CLOUDRU_SK_FILE", skPath)
	svc, err := newService()
	if err != nil {
		t.Fatal(err)
	}
	if svc.endpoint != "https://kms.example.com/root" || svc.project != "proj" || svc.ak != "AKID" || svc.skPath != skPath {
		t.Fatalf("service = %+v", svc)
	}
	tr, ok := svc.http.Transport.(*http.Transport)
	if !ok || tr.Proxy != nil {
		t.Fatal("proxy is not disabled")
	}
	if err := svc.http.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("CheckRedirect = %v", err)
	}
	got, err := svc.readSK()
	if err != nil || got != "secret" {
		t.Fatalf("readSK = %q, %v", got, err)
	}
}
