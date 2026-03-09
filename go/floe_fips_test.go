package floe

import (
	"crypto/fips140"
	"testing"
)

func TestFipsMode(t *testing.T) {
	if fips140.Enabled() != true {
		t.Fatal("not in FIPS mode")
	}
}
