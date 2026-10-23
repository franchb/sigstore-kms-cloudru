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

import "testing"

func TestParseReference(t *testing.T) {
	t.Parallel()
	id := "0d0466b0-e727-4d9c-b35d-f84bb474a37f"
	got, err := ParseReference("cloudru://" + id)
	if err != nil {
		t.Fatal(err)
	}
	if got != id {
		t.Fatalf("ParseReference() = %q", got)
	}
	for _, bad := range []string{
		"cloudru:///" + id,
		"cloudru://" + id + "/extra",
		"cloudru://" + id + "?x=1",
		"yckms://" + id,
		"cloudru://not-a-uuid",
	} {
		if _, err := ParseReference(bad); err == nil {
			t.Fatalf("ParseReference(%q) succeeded", bad)
		}
	}
}
