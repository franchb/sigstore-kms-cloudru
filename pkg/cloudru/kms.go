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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

const AlgorithmECDSASHA256 = "ECDSA_SHA_256"

type SignerVerifier struct {
	svc   *service
	keyID string
}

var _ kms.SignerVerifier = (*SignerVerifier)(nil)

func LoadSignerVerifier(ctx context.Context, resourceID string) (*SignerVerifier, error) {
	return loadSignerVerifier(ctx, resourceID, nil)
}

func loadSignerVerifier(ctx context.Context, resourceID string, svc *service) (*SignerVerifier, error) {
	ref := resourceID
	if !strings.Contains(resourceID, "://") {
		ref = "cloudru://" + resourceID
	}
	id, err := ParseReference(ref)
	if err != nil {
		return nil, err
	}
	if svc == nil {
		svc, err = newService()
		if err != nil {
			return nil, err
		}
	}
	if err := svc.describeKey(ctx, id); err != nil {
		return nil, err
	}
	return &SignerVerifier{svc: svc, keyID: id}, nil
}

func (s *SignerVerifier) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	ctx := context.Background()
	var digest []byte
	var signerOpts crypto.SignerOpts
	for _, opt := range opts {
		opt.ApplyContext(&ctx)
		opt.ApplyDigest(&digest)
		opt.ApplyCryptoSignerOpts(&signerOpts)
	}
	hashed, err := messageDigest(message, digest, signerOpts)
	if err != nil {
		return nil, err
	}
	raw, err := s.svc.signDigest(ctx, s.keyID, hashed)
	if err != nil {
		return nil, err
	}
	return derSignature(raw)
}

func messageDigest(message io.Reader, digest []byte, signerOpts crypto.SignerOpts) ([]byte, error) {
	var hashFunc crypto.Hash
	if signerOpts != nil {
		hashFunc = signerOpts.HashFunc()
	}
	if hashFunc != crypto.SHA256 && hashFunc != 0 {
		return nil, fmt.Errorf("cloudru: unsupported hash function %v", hashFunc)
	}
	if digest != nil {
		return digest, nil
	}
	if message == nil {
		return nil, errors.New("cloudru: message is nil")
	}
	buf, err := io.ReadAll(message)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(buf)
	return sum[:], nil
}

func derSignature(sig []byte) ([]byte, error) {
	if len(sig) == 64 {
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		return asn1.Marshal(struct{ R, S *big.Int }{r, s})
	}
	var parsed struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(sig, &parsed)
	if err != nil || len(rest) != 0 || parsed.R == nil || parsed.S == nil {
		return nil, errors.New("cloudru: signature is neither DER nor 64-byte r||s")
	}
	return sig, nil
}

func (s *SignerVerifier) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	ctx := context.Background()
	for _, opt := range opts {
		opt.ApplyContext(&ctx)
	}
	pemText, err := s.svc.getPublicKey(ctx, s.keyID)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, errors.New("cloudru: public key is not PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cloudru: parse public key: %w", err)
	}
	key, ok := pub.(*ecdsa.PublicKey)
	if !ok || key == nil || key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("cloudru: public key must be ECDSA P-256, got %T", pub)
	}
	return key, nil
}

func (s *SignerVerifier) VerifySignature(sig, message io.Reader, opts ...signature.VerifyOption) error {
	ctx := context.Background()
	var digest []byte
	var signerOpts crypto.SignerOpts
	for _, opt := range opts {
		opt.ApplyContext(&ctx)
		opt.ApplyDigest(&digest)
		opt.ApplyCryptoSignerOpts(&signerOpts)
	}
	hashed, err := messageDigest(message, digest, signerOpts)
	if err != nil {
		return err
	}
	if sig == nil {
		return errors.New("cloudru: signature is nil")
	}
	sigBytes, err := io.ReadAll(sig)
	if err != nil {
		return err
	}
	pub, err := s.PublicKey(options.WithContext(ctx))
	if err != nil {
		return err
	}
	key, ok := pub.(*ecdsa.PublicKey)
	if !ok || key == nil {
		return errors.New("cloudru: public key must be ECDSA P-256")
	}
	if !ecdsa.VerifyASN1(key, hashed, sigBytes) {
		return errors.New("cloudru: signature verification failed")
	}
	return nil
}

func (*SignerVerifier) CreateKey(context.Context, string) (crypto.PublicKey, error) {
	return nil, errors.New("cloudru: CreateKey is not supported")
}

type cryptoSignerWrapper struct {
	ctx      context.Context //nolint:containedctx // required by crypto.Signer Public/Sign API bridge
	sv       *SignerVerifier
	errFunc  func(error)
	hashFunc crypto.Hash
}

func (c cryptoSignerWrapper) Public() crypto.PublicKey {
	publicKey, err := c.sv.PublicKey(options.WithContext(c.ctx))
	if err != nil && c.errFunc != nil {
		c.errFunc(err)
	}
	return publicKey
}

func (c cryptoSignerWrapper) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hashFunc := c.hashFunc
	if opts != nil {
		hashFunc = opts.HashFunc()
	}
	return c.sv.SignMessage(nil, options.WithContext(c.ctx), options.WithDigest(digest), options.WithCryptoSignerOpts(hashFunc))
}

func (s *SignerVerifier) CryptoSigner(ctx context.Context, errFunc func(error)) (crypto.Signer, crypto.SignerOpts, error) {
	return &cryptoSignerWrapper{
		ctx:      ctx,
		sv:       s,
		errFunc:  errFunc,
		hashFunc: crypto.SHA256,
	}, crypto.SHA256, nil
}

func (*SignerVerifier) SupportedAlgorithms() []string { return []string{AlgorithmECDSASHA256} }

func (*SignerVerifier) DefaultAlgorithm() string { return AlgorithmECDSASHA256 }
