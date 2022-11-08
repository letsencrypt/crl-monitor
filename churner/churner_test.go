package churner

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRandDomains(t *testing.T) {
	churner := &Churner{baseDomain: "revoked.invalid"}
	domains := churner.RandDomains()
	require.Len(t, domains, 1)
	require.Regexp(t, regexp.MustCompile(`r[0-9]{10}z[0-9a-f]{4}\.revoked\.invalid`), domains[0])

	second := churner.RandDomains()
	require.NotEqual(t, domains, second, "Domains should be different each invocation")
}
