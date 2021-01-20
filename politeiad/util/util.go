// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package util

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/decred/dcrtime/merkle"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/util"
)

// MerkleRoot computes and returns the merkle root of the backend files.
func MerkleRoot(files []backend.File) (*[sha256.Size]byte, error) {
	digests := make([]*[sha256.Size]byte, 0, len(files))
	for _, v := range files {
		// Decode digest
		digest, err := hex.DecodeString(v.Digest)
		if err != nil {
			return nil, err
		}

		// Decode payload
		payload, err := base64.StdEncoding.DecodeString(v.Payload)
		if err != nil {
			return nil, err
		}

		// Verify digest
		d := util.Digest(payload)
		if bytes.Equal(digest, d) {
			return nil, fmt.Errorf("invalid digest for payload: got %x, want %x",
				digest, d)
		}

		// Save digest
		var s [sha256.Size]byte
		copy(s[:], d)
		digests = append(digests, &s)
	}

	// Calc merkle root
	return merkle.Root(digests), nil
}
