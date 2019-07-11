// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package util

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	v1 "github.com/decred/politeia/tlog/api/v1"
)

// RecordEntryVerify ensures that a tlog RecordEntry is valid.
func RecordEntryVerify(record v1.RecordEntry) error {
	// Decode identity
	id, err := IdentityFromString(record.PublicKey)
	if err != nil {
		return err
	}

	// Decode hash
	hash, err := hex.DecodeString(record.Hash)
	if err != nil {
		return err
	}

	// Decode signature
	s, err := hex.DecodeString(record.Signature)
	if err != nil {
		return err
	}
	var signature [64]byte
	copy(signature[:], s)

	// Decode data
	data, err := base64.StdEncoding.DecodeString(record.Data)
	if err != nil {
		return err
	}
	// Verify hash
	h := sha256.New()
	h.Write(data)
	if !bytes.Equal(hash, h.Sum(nil)) {
		return fmt.Errorf("invalid hash")
	}

	// Verify signature
	if !id.VerifyMessage([]byte(record.Hash), signature) {
		return fmt.Errorf("invalid signature")
	}

	return nil
}
