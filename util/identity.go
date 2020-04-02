// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package util

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/thi4go/politeia/politeiad/api/v1"
	"github.com/thi4go/politeia/politeiad/api/v1/identity"
)

// IdentityFromString converts a string public key into a public identity
// structure.
func IdentityFromString(id string) (*identity.PublicIdentity, error) {
	pk, err := hex.DecodeString(id)
	if err != nil {
		return nil, err
	}
	return identity.PublicIdentityFromBytes(pk)
}

// RemoteIdentity fetches the identity from politeiad.
func RemoteIdentity(skipTLSVerify bool, host, cert string) (*identity.PublicIdentity, error) {
	challenge, err := Random(v1.ChallengeSize)
	if err != nil {
		return nil, err
	}
	id, err := json.Marshal(v1.Identity{
		Challenge: hex.EncodeToString(challenge),
	})
	if err != nil {
		return nil, err
	}

	c, err := NewClient(skipTLSVerify, cert)
	if err != nil {
		return nil, err
	}
	r, err := c.Post(host+v1.IdentityRoute, "application/json",
		bytes.NewReader(id))
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		e, err := GetErrorFromJSON(r.Body)
		if err != nil {
			return nil, fmt.Errorf("%v", r.Status)
		}
		return nil, fmt.Errorf("%v: %v", r.Status, e)
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	var ir v1.IdentityReply
	err = json.Unmarshal(body, &ir)
	if err != nil {
		return nil, fmt.Errorf("Could node unmarshal IdentityReply: %v",
			err)
	}

	// Convert and verify server identity
	identity, err := IdentityFromString(ir.PublicKey)
	if err != nil {
		return nil, err
	}

	err = VerifyChallenge(identity, challenge, ir.Response)
	if err != nil {
		return nil, err
	}

	return identity, nil
}

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
