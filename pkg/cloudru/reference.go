package cloudru

import (
	"fmt"
	"regexp"
	"strings"
)

const ReferenceScheme = "cloudru://"

var keyID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func ParseReference(ref string) (string, error) {
	id, ok := strings.CutPrefix(ref, ReferenceScheme)
	if !ok || !keyID.MatchString(id) {
		return "", fmt.Errorf("cloudru: key reference must be cloudru://<uuid>, got %q", ref)
	}
	return id, nil
}
