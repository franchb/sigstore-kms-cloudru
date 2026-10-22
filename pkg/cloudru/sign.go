package cloudru

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

func signRequest(req *http.Request, ak, sk string, when time.Time) error {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return err
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.Header.Set("X-Sdk-Date", when.UTC().Format("20060102T150405Z"))
	req.Header.Set("Host", req.URL.Host)

	names := make([]string, 0, len(req.Header))
	for name := range req.Header {
		names = append(names, strings.ToLower(name))
	}
	sort.Strings(names)
	var headers strings.Builder
	for _, name := range names {
		headers.WriteString(name)
		headers.WriteByte(':')
		headers.WriteString(strings.TrimSpace(req.Header.Get(name)))
		headers.WriteByte('\n')
	}
	signed := strings.Join(names, ";")
	path := req.URL.EscapedPath()
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}
	sum := sha256.Sum256(body)
	canonical := strings.Join([]string{
		req.Method,
		path,
		req.URL.RawQuery,
		headers.String(),
		signed,
		hex.EncodeToString(sum[:]),
	}, "\n")
	hashed := sha256.Sum256([]byte(canonical))
	stringToSign := "SDK-HMAC-SHA256\n" + req.Header.Get("X-Sdk-Date") + "\n" + hex.EncodeToString(hashed[:])
	mac := hmac.New(sha256.New, []byte(sk))
	_, _ = mac.Write([]byte(stringToSign))
	signature := hex.EncodeToString(mac.Sum(nil))
	req.Header.Set("Authorization", fmt.Sprintf(
		"SDK-HMAC-SHA256 Access=%s, SignedHeaders=%s, Signature=%s",
		ak, signed, signature,
	))
	return nil
}
