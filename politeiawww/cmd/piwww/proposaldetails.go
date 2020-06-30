// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// ProposalDetailsCmd retrieves the details of a proposal.
type ProposalDetailsCmd struct {
	Args struct {
		Token   string `positional-arg-name:"token" required:"true"` // Censorship token
		Version string `positional-arg-name:"version"`               // Proposal version
	} `positional-args:"true"`
}

// Execute executes the proposal details command.
func (cmd *ProposalDetailsCmd) Execute(args []string) error {
	// Get server's public key
	vr, err := client.Version()
	if err != nil {
		return err
	}

	if len(cmd.Args.Token) == www.TokenPrefixLength && cmd.Args.Version != "" {
		fmt.Println("VERSION ARGUMENT CANNOT BE USED WITH TOKEN PREFIX!!")
	}

	// Get proposal
	pdr, err := client.ProposalDetails(cmd.Args.Token,
		&www.ProposalsDetails{
			Version: cmd.Args.Version,
		})
	if err != nil {
		return err
	}

	// Verify proposal censorship record
	err = shared.VerifyProposal(pdr.Proposal, vr.PubKey)
	if err != nil {
		return fmt.Errorf("unable to verify proposal %v: %v",
			pdr.Proposal.CensorshipRecord.Token, err)
	}

	// Print proposal details
	return shared.PrintJSON(pdr)
}

// proposalDetailsHelpMsg is the output for the help command when
// 'proposaldetails' is specified.
const proposalDetailsHelpMsg = `proposaldetails "token" "version"

Get a proposal.

The 7 character prefix of the token can also be used instead of the full token,
but when using the token prefix, only the latest version can be retrieved.

Arguments:
1. token      (string, required)   Censorship token
2. version    (string, optional)   Proposal version

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
