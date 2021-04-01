// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package util

import (
	"fmt"
	"testing"

	"github.com/decred/dcrd/chaincfg/v3"
)

func TestErrorStatuses(t *testing.T) {
	// Iterate through all error statuses and verify that a human
	// readable error message exists.
	missing := make([]ErrorStatusT, 0, len(ErrorStatuses))
	for i := 0; i < int(errorStatusLast); i++ {
		e := ErrorStatusT(i)
		_, ok := ErrorStatuses[e]
		if !ok {
			// We're missing a error message
			missing = append(missing, e)
		}

		// The entry was found. Delete it. This will allow us to
		// determine if there are any extra error messages in the
		// map at the end.
		delete(ErrorStatuses, e)
	}

	// Verify there are not any missing error messsages
	if len(missing) > 0 {
		t.Errorf("error messages missing for codes: %v", missing)
	}

	// Verify there are not any extra error messages. They should all
	// be deleted at this point. If any still exists then those are
	// extra and should not be there.
	if len(ErrorStatuses) > 0 {
		t.Errorf("extra error messages found: %v", ErrorStatuses)
	}
}

func TestVerifyMessage(t *testing.T) {
	// The following example is mimicking a politeia dcr ticket vote
	var (
		token   = "09bad4b668aec651"
		ticket  = "f30add902bd7ec56b2b27204dbd1219b875c9a8e8832ff845c4282847ea59918"
		votebit = "1"
		msg     = token + ticket + votebit
		address = "TsdjFrFyyKZMpPu1NNwnH9CTs5kkp4X7KVf"
		net     = chaincfg.TestNet3Params()

		signature = "H5TQz6ASvJGobe/0V9g2lBKC8oraWxzNtliqxBwnPgXSU+4aennJ5zuY7uwOM/MBh/UuhBMJwYuWDQOctYwPouU="

		// This is a valid signature that uses a different message and
		// address than the ones listed above.
		wrongSignature = "INqYmFhIOaPFbtRbSBYs7xbQ976OgvdD5rKtbfnDe1uHOlxS+qIXmqxRnpodIvBHEGgU1dI0eSyZpZGharmPh2k="
	)

	var tests = []struct {
		name    string // Test name
		addr    string // P2PKH address
		msg     string // Message being signed
		sig     string // Signature
		isValid bool   // Is the signature valid
	}{
		{
			"address in not a valid",
			"xxx",
			msg,
			signature,
			false,
		},
		{
			"address is not p2pkh",
			"TkdjFrFyyKZMpPu1NNwnH9CTs5kkp4X7KVf",
			msg,
			signature,
			false,
		},
		{
			"signature is not base64",
			address,
			msg,
			"xxx",
			false,
		},
		{
			"signature is wrong",
			address,
			msg,
			wrongSignature,
			false,
		},
		{
			"success",
			address,
			msg,
			signature,
			true,
		},
	}
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			isValid, err := VerifyMessage(v.addr, v.msg, v.sig, net)
			if isValid != v.isValid {
				fmt.Printf("isValid %v: %v\n", isValid, err)
				t.Errorf("VerifyMessage: is valid got %v, want %v",
					isValid, v.isValid)
			}
		})
	}
}
