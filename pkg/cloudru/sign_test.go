package cloudru

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSignRequestVector(t *testing.T) {
	t.Parallel()
	req, err := http.NewRequest(http.MethodPost, "https://kms.example.com/v1.0/project-id/kms/sign", strings.NewReader(`{"key_id":"k"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Project-Id", "project-id")
	when := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	if err := signRequest(req, "AKID", "secret-access-key", when); err != nil {
		t.Fatal(err)
	}
	got := req.Header.Get("Authorization")
	want := "SDK-HMAC-SHA256 Access=AKID, SignedHeaders=content-type;host;x-project-id;x-sdk-date, Signature=1b68580d8647f90d6c9bde702baa3b5d80b5eb7015da070b8915e0a86acdc723"
	if got != want {
		t.Fatalf("Authorization = %q", got)
	}
	if req.Header.Get("X-Sdk-Date") != "20261022T120000Z" {
		t.Fatalf("X-Sdk-Date = %q", req.Header.Get("X-Sdk-Date"))
	}
}
