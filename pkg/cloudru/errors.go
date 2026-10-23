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

import "errors"

var (
	errConfigRequired = errors.New("cloudru: CLOUDRU_PROJECT_ID, CLOUDRU_AK, and CLOUDRU_SK_FILE are required")
	errBadEndpoint    = errors.New(
		"cloudru: endpoint must be an https URL with a host and no userinfo, query, or fragment",
	)
	errEmptySK       = errors.New("cloudru: secret key is empty")
	errKeyInfoShape  = errors.New("cloudru: key_info must be an object or a one-element array")
	errKeyInfoLength = errors.New("cloudru: key_info array must contain exactly one object")
	errBadKeySpec    = errors.New("cloudru: unsupported key_spec")
	errBadKeyUsage   = errors.New("cloudru: unsupported key_usage")
	errBadReference  = errors.New("cloudru: key reference must be cloudru://<uuid>")
	errBadHash       = errors.New("cloudru: unsupported hash function")
	errNilMessage    = errors.New("cloudru: message is nil")
	errBadSignature  = errors.New("cloudru: signature is neither DER nor 64-byte r||s")
	errPublicKeyPEM  = errors.New("cloudru: public key is not PEM")
	errPublicKeyP256 = errors.New("cloudru: public key must be ECDSA P-256")
	errNilSignature  = errors.New("cloudru: signature is nil")
	errVerifyFailed  = errors.New("cloudru: signature verification failed")
	errCreateKey     = errors.New("cloudru: CreateKey is not supported")
	errRemote        = errors.New("cloudru")
)
