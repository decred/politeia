package util

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/decred/dcrtime/api/v1"
)

// ConvertStringToken verifies and converts a string token to a proper sized
// []byte.
func ConvertStringToken(token string) ([]byte, error) {
	if len(token) != 64 {
		return nil, fmt.Errorf("invalid censorship token size")
	}
	blob, err := hex.DecodeString(token)
	if err != nil {
		return nil, err
	}
	return blob, nil
}

// Digest returns the SHA256 of a byte slice.
func Digest(b []byte) []byte {
	h := sha256.New()
	h.Write(b)
	return h.Sum(nil)
}

// IsDigest determines if a string is a valid SHA256 digest.
func IsDigest(digest string) bool {
	return v1.RegexpSHA256.MatchString(digest)
}

// ConvertDigest converts a string into a digest.
func ConvertDigest(d string) ([sha256.Size]byte, bool) {
	var digest [sha256.Size]byte
	if !IsDigest(d) {
		return digest, false
	}

	dd, err := hex.DecodeString(d)
	if err != nil {
		return digest, false
	}
	copy(digest[:], dd)

	return digest, true
}
