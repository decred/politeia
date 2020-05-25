package util

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/decred/dcrtime/merkle"
	v1 "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/util"
)

// MerkleRoot converts the passed in list of files and metadata into SHA256
// digests then calculates and returns the merkle root of the digests. It
// also applies proper validation for the files and metadata digests.
func MerkleRoot(files []v1.File, md []v1.Metadata) (string, error) {
	if len(files) == 0 {
		return "", fmt.Errorf("no files found")
	}

	// Validate file digests
	digests := make([]*[sha256.Size]byte, 0, len(files))
	for _, f := range files {
		b, err := base64.StdEncoding.DecodeString(f.Payload)
		if err != nil {
			return "", fmt.Errorf("file: %v decode payload err %v",
				f.Name, err)
		}
		digest := util.Digest(b)
		d, ok := util.ConvertDigest(f.Digest)
		if !ok {
			return "", fmt.Errorf("file: %v invalid digest %v",
				f.Name, f.Digest)
		}
		if !bytes.Equal(digest, d[:]) {
			return "", fmt.Errorf("file: %v digests do not match",
				f.Name)
		}

		// Digest is valid
		digests = append(digests, &d)
	}

	// Validate metadata digests
	for _, v := range md {
		b, err := base64.StdEncoding.DecodeString(v.Payload)
		if err != nil {
			return "", fmt.Errorf("metadata: %v decode payload err %v",
				v.Hint, err)
		}
		digest := util.Digest(b)
		d, ok := util.ConvertDigest(v.Digest)
		if !ok {
			return "", fmt.Errorf("metadata: %v invalid digest %v",
				v.Hint, v.Digest)
		}
		if !bytes.Equal(digest, d[:]) {
			return "", fmt.Errorf("metadata: %v digests do not match",
				v.Hint)
		}

		// Digest is valid
		digests = append(digests, &d)
	}

	// Return merkle root
	return hex.EncodeToString(merkle.Root(digests)[:]), nil
}

// DigestUserError this function converts the error provided by
// MerkleRoot to its appropriate UserError, depending on which
// step of the validation it failed, when verifying file digests
// or metadata digests.
func DigestUserError(err error) v1.UserError {
	str := err.Error()
	ue := v1.UserError{
		ErrorCode:    v1.ErrorStatusInvalidFileDigest,
		ErrorContext: []string{str},
	}
	if strings.Contains(str, "metadata") {
		ue.ErrorCode = v1.ErrorStatusMetadataDigestInvalid
	}
	return ue
}
