// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package util

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	dcrtime "github.com/decred/dcrtime/api/v1"
	pdv1 "github.com/decred/politeia/politeiad/api/v1"
	pdv2 "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/identity"
)

// ConvertSignature converts a hex encoded signature to a proper sized byte
// slice.
func ConvertSignature(s string) ([identity.SignatureSize]byte, error) {
	sb, err := hex.DecodeString(s)
	if err != nil {
		return [identity.SignatureSize]byte{}, err
	}
	if len(sb) != identity.SignatureSize {
		return [identity.SignatureSize]byte{},
			fmt.Errorf("invalid signature length")
	}
	var sig [identity.SignatureSize]byte
	copy(sig[:], sb)
	return sig, nil
}

// ConvertStringToken verifies and converts a string token to a proper sized
// byte slice. This function accepts both the full length token and token
// prefixes.
func ConvertStringToken(token string) ([]byte, error) {
	switch {
	case len(token) == pdv2.TokenSize*2:
		// Tstore backend token; continue
	case len(token) != pdv1.TokenSize*2:
		// Git backend token; continue
	case len(token) == pdv1.TokenPrefixLength:
		// Token prefix; continue
	default:
		return nil, fmt.Errorf("invalid token size")
	}
	// If the token length is an odd number of characters, append a
	// 0 digit as padding to prevent a hex.ErrLenth (odd length hex
	// string) error when decoding.
	if len(token)%2 == 1 {
		token = token + "0"
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
	return dcrtime.RegexpSHA256.MatchString(digest)
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

// TokenToPrefix returns a substring a token of length pd.TokenPrefixLength,
// or the token itself, whichever is shorter.
func TokenToPrefix(token string) string {
	if len(token) > pdv1.TokenPrefixLength {
		return token[0:pdv1.TokenPrefixLength]
	} else {
		return token
	}
}

// TokensToPrefixes calls TokenToPrefix on a slice of tokens.
func TokensToPrefixes(tokens []string) []string {
	prefixes := make([]string, 0, len(tokens))
	for _, token := range tokens {
		prefixes = append(prefixes, TokenToPrefix(token))
	}
	return prefixes
}
