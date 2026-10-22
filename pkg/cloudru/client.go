package cloudru

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type service struct {
	endpoint string // validated https URL; trailing slash optional
	project  string
	ak       string
	skPath   string
	http     *http.Client
}

func newService() (*service, error) {
	endpoint, err := parseEndpoint(os.Getenv("CLOUDRU_KMS_ENDPOINT"))
	if err != nil {
		return nil, err
	}
	project := os.Getenv("CLOUDRU_PROJECT_ID")
	ak := os.Getenv("CLOUDRU_AK")
	skPath := os.Getenv("CLOUDRU_SK_FILE")
	if project == "" || ak == "" || skPath == "" {
		return nil, errors.New("cloudru: CLOUDRU_PROJECT_ID, CLOUDRU_AK, and CLOUDRU_SK_FILE are required")
	}
	return &service{
		endpoint: endpoint,
		project:  project,
		ak:       ak,
		skPath:   skPath,
		http:     newHTTPClient(),
	}, nil
}

func parseEndpoint(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return "", errors.New("cloudru: endpoint must be an https URL with a host and no userinfo, query, or fragment")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	return u.String(), nil
}

func newHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (s *service) readSK() (string, error) {
	b, err := os.ReadFile(s.skPath)
	if err != nil {
		return "", fmt.Errorf("cloudru: read secret key: %w", err)
	}
	sk := strings.TrimSpace(string(b))
	if sk == "" {
		return "", errors.New("cloudru: secret key is empty")
	}
	return sk, nil
}

type keyIDBody struct {
	KeyID string `json:"key_id"`
}

type signBody struct {
	KeyID            string `json:"key_id"`
	Message          string `json:"message"`
	MessageType      string `json:"message_type"`
	SigningAlgorithm string `json:"signing_algorithm"`
}

func (s *service) describeKey(ctx context.Context, keyID string) error {
	body, err := s.post(ctx, "describe-key", keyIDBody{KeyID: keyID})
	if err != nil {
		return err
	}
	return validateKeyInfo(body)
}

func (s *service) signDigest(ctx context.Context, keyID string, digest []byte) ([]byte, error) {
	body, err := s.post(ctx, "sign", signBody{
		KeyID:            keyID,
		Message:          base64.StdEncoding.EncodeToString(digest),
		MessageType:      "DIGEST",
		SigningAlgorithm: "ECDSA_SHA_256",
	})
	if err != nil {
		return nil, err
	}
	var out struct {
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("cloudru: decode sign response: %w", err)
	}
	raw, err := base64.StdEncoding.DecodeString(out.Signature)
	if err != nil {
		return nil, fmt.Errorf("cloudru: decode signature: %w", err)
	}
	return raw, nil
}

func (s *service) getPublicKey(ctx context.Context, keyID string) (string, error) {
	body, err := s.post(ctx, "get-publickey", keyIDBody{KeyID: keyID})
	if err != nil {
		return "", err
	}
	var out struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("cloudru: decode get-publickey response: %w", err)
	}
	return out.PublicKey, nil
}

func (s *service) post(ctx context.Context, action string, payload any) ([]byte, error) {
	sk, err := s.readSK()
	if err != nil {
		return nil, err
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	rawURL := strings.TrimRight(s.endpoint, "/") + "/v1.0/" + url.PathEscape(s.project) + "/kms/" + action
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Project-Id", s.project)
	ak := s.ak
	if err := signRequest(req, ak, sk, time.Now().UTC()); err != nil {
		return nil, err
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("cloudru: %s: %s (%s)", resp.Status, scrub(string(body), ak, sk), time.Now().UTC().Format(time.RFC3339))
	}
	return body, nil
}

func validateKeyInfo(body []byte) error {
	var envelope struct {
		KeyInfo json.RawMessage `json:"key_info"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return fmt.Errorf("cloudru: decode describe-key: %w", err)
	}
	raw := bytes.TrimSpace(envelope.KeyInfo)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return errors.New("cloudru: key_info must be an object or a one-element array")
	}
	var got struct {
		KeySpec  string `json:"key_spec"`
		KeyUsage string `json:"key_usage"`
	}
	switch raw[0] {
	case '{':
		if err := json.Unmarshal(raw, &got); err != nil {
			return fmt.Errorf("cloudru: decode key_info: %w", err)
		}
	case '[':
		var arr []json.RawMessage
		if err := json.Unmarshal(raw, &arr); err != nil {
			return fmt.Errorf("cloudru: decode key_info: %w", err)
		}
		if len(arr) != 1 {
			return errors.New("cloudru: key_info array must contain exactly one object")
		}
		item := bytes.TrimSpace(arr[0])
		if len(item) == 0 || item[0] != '{' {
			return errors.New("cloudru: key_info array must contain exactly one object")
		}
		if err := json.Unmarshal(item, &got); err != nil {
			return fmt.Errorf("cloudru: decode key_info: %w", err)
		}
	default:
		return errors.New("cloudru: key_info must be an object or a one-element array")
	}
	if got.KeySpec != "EC_P256" {
		return fmt.Errorf("cloudru: unsupported key_spec %q", got.KeySpec)
	}
	if got.KeyUsage != "SIGN_VERIFY" {
		return fmt.Errorf("cloudru: unsupported key_usage %q", got.KeyUsage)
	}
	return nil
}

// scrub redacts sk, then ak, then keeps at most 300 bytes.
func scrub(body, ak, sk string) string {
	if sk != "" {
		body = strings.ReplaceAll(body, sk, "[redacted]")
	}
	if ak != "" {
		body = strings.ReplaceAll(body, ak, "[redacted]")
	}
	b := []byte(body)
	if len(b) > 300 {
		b = b[:300]
	}
	return string(b)
}
