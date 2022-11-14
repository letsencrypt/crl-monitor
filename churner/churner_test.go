package churner

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRandDomains(t *testing.T) {
	base := "revoked.invalid"
	domains := randDomains(base)
	require.Len(t, domains, 1)
	require.Regexp(t, regexp.MustCompile(`r[0-9]{10}z[0-9a-f]{4}\.`+regexp.QuoteMeta(base)), domains[0])

	second := randDomains(base)
	require.NotEqual(t, domains, second, "Domains should be different each invocation")
}
