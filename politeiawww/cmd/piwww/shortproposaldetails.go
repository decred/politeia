// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// ShortProposalDetailsCmd retrieves the details of a proposal using its
// token's prefix.
type ShortProposalDetailsCmd struct {
	Args struct {
		Prefix string `positional-arg-name:"tokenPrefix" required:"true"`
	} `positional-args:"true"`
}

// Execute executes the short proposal details command.
func (cmd *ShortProposalDetailsCmd) Execute(args []string) error {
	// Get server's public key
	vr, err := client.Version()
	if err != nil {
		return err
	}

	// Get proposal
	pdr, err := client.ShortProposalDetails(cmd.Args.Prefix)
	if err != nil {
		return err
	}

	// Verify proposal censorship record
	err = verifyProposal(pdr.Proposal, vr.PubKey)
	if err != nil {
		return fmt.Errorf("unable to verify proposal %v: %v",
			pdr.Proposal.CensorshipRecord.Token, err)
	}

	// Print proposal details
	return shared.PrintJSON(pdr)
}

// shortProposalDetailsHelpMsg is the output for the help command when
// 'shortproposaldetails' is specified.
const shortProposalDetailsHelpMsg = `shortproposaldetails "tokenPrefix"

Get a proposal using the prefix of a token. The length of the prefix can be
determined using the version route.

Arguments:
1. tokenPrefix      (string, required)   Prefix of censorship token

Result:
{
  "proposal": {
    "name":          (string)  Suggested short proposal name 
    "state":         (PropStateT)  Current state of proposal
    "status":        (PropStatusT)  Current status of proposal
    "timestamp":     (int64)  Timestamp of last update of proposal
    "userid":        (string)  ID of user who submitted proposal
    "username":      (string)  Username of user who submitted proposal
    "publickey":     (string)  Public key used to sign proposal
    "signature":     (string)  Signature of merkle root
    "files": [
      {
        "name":      (string)  Filename 
        "mime":      (string)  Mime type 
        "digest":    (string)  File digest 
        "payload":   (string)  File payload 
      }
    ],
    "numcomments":   (uint)  Number of comments on the proposal
    "version": 		 (string)  Version of proposal
    "censorshiprecord": {	
      "token":       (string)  Censorship token
      "merkle":      (string)  Merkle root of proposal
      "signature":   (string)  Server side signature of []byte(Merkle+Token)
    }
  }
}`
