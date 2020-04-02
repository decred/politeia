// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package util

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/decred/dcrtime/api/v1"
	pd "github.com/thi4go/politeia/politeiad/api/v1"
	"github.com/thi4go/politeia/politeiad/api/v1/identity"
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
// []byte.
func ConvertStringToken(token string) ([]byte, error) {
	if len(token) != pd.TokenSize*2 {
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

// Zero out a byte slice.
func Zero(in []byte) {
	if in == nil {
		return
	}
	inlen := len(in)
	for i := 0; i < inlen; i++ {
		in[i] ^= in[i]
	}
}
