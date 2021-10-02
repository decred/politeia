// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package util

import (
	"encoding/hex"
	"fmt"

	"github.com/decred/politeia/politeiad/api/v1/identity"
)

// VerifyChallenge checks that the signature returned from politeiad is the
// challenge signed with the given identity.
func VerifyChallenge(id *identity.PublicIdentity, challenge []byte, signature string) error {
	// Verify challenge.
	s, err := hex.DecodeString(signature)
	if err != nil {
		return err
	}
	var sig [identity.SignatureSize]byte
	copy(sig[:], s)
	if !id.VerifyMessage(challenge, sig) {
		return fmt.Errorf("challenge verification failed")
	}

	return nil
}
