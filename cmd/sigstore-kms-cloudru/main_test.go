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

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/common"

	"github.com/franchb/sigstore-kms-cloudru/pkg/cloudru"
)

const pluginArgv0 = "sigstore-kms-cloudru"

var errLoaderBoom = errors.New("loader boom")

func TestRunMissingProtocolVersion(t *testing.T) {
	t.Parallel()

	code, stdout := runPlugin(t, nil, stubLoader(t))
	if code == 0 {
		t.Fatalf("run() = %d, want non-zero", code)
	}

	if !strings.Contains(stdout, "protocol version") {
		t.Fatalf("stdout = %q, want protocol version", stdout)
	}
}

func TestRunWrongProtocolVersion(t *testing.T) {
	t.Parallel()

	code, stdout := runPlugin(t, []string{pluginArgv0, "v0"}, stubLoader(t))
	if code == 0 {
		t.Fatalf("run() = %d, want non-zero", code)
	}

	if !strings.Contains(stdout, "v1") {
		t.Fatalf("stdout = %q, want protocol version v1", stdout)
	}
}

func TestRunEmptyPluginJSON(t *testing.T) {
	t.Parallel()

	code, stdout := runPlugin(t, []string{pluginArgv0, "v1", "{}"}, stubLoader(t))
	if code == 0 {
		t.Fatalf("run() = %d, want non-zero", code)
	}

	if !strings.Contains(stdout, errIncompletePluginArgs.Error()) {
		t.Fatalf("stdout = %q, want %q", stdout, errIncompletePluginArgs)
	}
}

func TestRunLoaderError(t *testing.T) {
	t.Parallel()

	const keyResourceID = "cloudru://11111111-2222-3333-4444-555555555555"

	called := false
	load := func(_ context.Context, resourceID string) (*cloudru.SignerVerifier, error) {
		called = true
		if resourceID != keyResourceID {
			t.Errorf("loader resourceID = %q, want %q", resourceID, keyResourceID)
		}
		return nil, errLoaderBoom
	}

	args := []string{pluginArgv0, "v1", defaultAlgorithmPluginJSON(t, keyResourceID)}

	code, stdout := runPlugin(t, args, load)
	if code == 0 {
		t.Fatalf("run() = %d, want non-zero", code)
	}

	if !called {
		t.Fatal("loader was not invoked")
	}

	if !strings.Contains(stdout, errLoaderBoom.Error()) {
		t.Fatalf("stdout = %q, want %q", stdout, errLoaderBoom)
	}
}

func stubLoader(t *testing.T) func(context.Context, string) (*cloudru.SignerVerifier, error) {
	t.Helper()

	return func(context.Context, string) (*cloudru.SignerVerifier, error) {
		t.Fatal("loader must not be called")
		return nil, nil
	}
}

func runPlugin(
	t *testing.T,
	args []string,
	load func(context.Context, string) (*cloudru.SignerVerifier, error),
) (int, string) {
	t.Helper()

	var stdout bytes.Buffer

	code := run(args, bytes.NewReader(nil), &stdout, load)

	return code, stdout.String()
}

func defaultAlgorithmPluginJSON(t *testing.T, keyResourceID string) string {
	t.Helper()

	payload, err := json.Marshal(common.PluginArgs{
		InitOptions: &common.InitOptions{
			CtxDeadline:     nil,
			ProtocolVersion: "v1",
			KeyResourceID:   keyResourceID,
			HashFunc:        0,
			RPCOptions:      nil,
		},
		MethodArgs: &common.MethodArgs{
			MethodName:          common.DefaultAlgorithmMethodName,
			DefaultAlgorithm:    &common.DefaultAlgorithmArgs{},
			SupportedAlgorithms: nil,
			CreateKey:           nil,
			PublicKey:           nil,
			SignMessage:         nil,
			VerifySignature:     nil,
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	return string(payload)
}
