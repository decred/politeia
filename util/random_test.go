package util_test

import (
	"github.com/decred/politeia/util"
	"testing"
)

func TestRandomUniqueToken(t *testing.T) {
	existingPrefixes := make([]string, 0, 256)

	for i := 0; i < 256; i++ {
		token, err := util.RandomUniqueToken(existingPrefixes, 64)
		if err != nil {
			t.Fatalf("Should be able to create 256 tokens with unique prefix"+
				" of length 2, but only created %d.", i)
		}
		existingPrefixes = append(existingPrefixes, token[0:2])
	}

	_, err := util.RandomUniqueToken(existingPrefixes, 64)
	if err == nil {
		t.Fatalf("Should only be able to create 256 tokens with unique " +
			"prefix of length 2, but was able to create 256")
	}
}
