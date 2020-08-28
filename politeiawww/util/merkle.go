// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package util

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"

	"github.com/decred/dcrtime/merkle"
	pi "github.com/decred/politeia/politeiawww/api/pi/v1"
	"github.com/decred/politeia/util"
)

// MerkleRoot converts the passed in list of files and metadata into SHA256
// digests then calculates and returns the merkle root of the digests.
func MerkleRoot(files []pi.File, md []pi.Metadata) (string, error) {
	digests := make([]*[sha256.Size]byte, 0, len(files))

	// Calculate file digests
	for _, f := range files {
		b, err := base64.StdEncoding.DecodeString(f.Payload)
		if err != nil {
			return "", err
		}
		digest := util.Digest(b)
		var hf [sha256.Size]byte
		copy(hf[:], digest)
		digests = append(digests, &hf)
	}

	// Calculate metadata digests
	for _, v := range md {
		b, err := base64.StdEncoding.DecodeString(v.Payload)
		if err != nil {
			return "", err
		}
		digest := util.Digest(b)
		var hv [sha256.Size]byte
		copy(hv[:], digest)
		digests = append(digests, &hv)
	}

	// Return merkle root
	return hex.EncodeToString(merkle.Root(digests)[:]), nil
}
