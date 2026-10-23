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

func FuzzParseReference(f *testing.F) {
	const id = "0d0466b0-e727-4d9c-b35d-f84bb474a37f"
	f.Add("cloudru://" + id)
	f.Add(id)
	f.Add("")
	f.Add("cloudru://" + "0D0466B0-E727-4D9C-B35D-F84BB474A37F")
	f.Add("not-a-uuid")
	f.Fuzz(func(_ *testing.T, ref string) {
		_, _ = ParseReference(ref)
	})
}
