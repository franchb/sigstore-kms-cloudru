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
