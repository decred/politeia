// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	v1 "github.com/thi4go/politeia/politeiawww/api/www/v1"
	"github.com/thi4go/politeia/politeiawww/cmd/shared"
)

// BatchProposalsCmd retrieves a set of proposals.
type BatchProposalsCmd struct{}

// Execute executes the batch proposals command.
func (cmd *BatchProposalsCmd) Execute(args []string) error {
	// Get server's public key
	vr, err := client.Version()
	if err != nil {
		return err
	}

	// Get proposals
	bpr, err := client.BatchProposals(&v1.BatchProposals{
		Tokens: args,
	})
	if err != nil {
		return err
	}

	// Verify proposal censorship records
	for _, p := range bpr.Proposals {
		err = verifyProposal(p, vr.PubKey)
		if err != nil {
			return fmt.Errorf("unable to verify proposal %v: %v",
				p.CensorshipRecord.Token, err)
		}
	}

	// Print proposals
	return shared.PrintJSON(bpr)
}

// batchProposalsHelpMsg is the output for the help command when
// 'batchproposals' is specified.
const batchProposalsHelpMsg = `batchproposals

Fetch a list of proposals.

Example:
batchproposals token1 token2

Result:
{
  "proposals": [
    {
    "name":          (string)  Suggested short proposal name 
    "state":         (PropStateT)  Current state of proposal
    "status":        (PropStatusT)  Current status of proposal
    "timestamp":     (int64)  Timestamp of last update of proposal
    "userid":        (string)  ID of user who submitted proposal
    "username":      (string)  Username of user who submitted proposal
    "publickey":     (string)  Public key used to sign proposal
    "signature":     (string)  Signature of merkle root
    "files": [],
    "numcomments":   (uint)  Number of comments on the proposal
    "version": 		 (string)  Version of proposal
    "censorshiprecord": {	
      "token":       (string)  Censorship token
      "merkle":      (string)  Merkle root of proposal
      "signature":   (string)  Server side signature of []byte(Merkle+Token)
      }
    }
  ]
}`
