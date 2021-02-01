// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package util

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/decred/dcrtime/merkle"
)

// MerkleRoot computes and returns the merkle root of the provided digests.
// The digests should be hex encoded SHA256 digests.
func MerkleRoot(digests []string) (*[sha256.Size]byte, error) {
	sha := make([]*[sha256.Size]byte, 0, len(digests))
	for _, v := range digests {
		// Decode digest
		d, err := hex.DecodeString(v)
		if err != nil {
			return nil, err
		}

		// Save digest
		var s [sha256.Size]byte
		copy(s[:], d)
		sha = append(sha, &s)
	}

	// Calc merkle root
	return merkle.Root(sha), nil
}
