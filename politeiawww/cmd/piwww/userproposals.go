// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/thi4go/politeia/politeiawww/api/www/v1"
	"github.com/thi4go/politeia/politeiawww/cmd/shared"
)

// UserProposalsCmd gets the proposals for the specified user.
type UserProposalsCmd struct {
	Args struct {
		UserID string `positional-arg-name:"userID"` // User ID
	} `positional-args:"true" required:"true"`
}

// Execute executes the user proposals command.
func (cmd *UserProposalsCmd) Execute(args []string) error {
	// Get server public key
	vr, err := client.Version()
	if err != nil {
		return err
	}

	// Get user proposals
	upr, err := client.UserProposals(
		&v1.UserProposals{
			UserId: cmd.Args.UserID,
		})
	if err != nil {
		return err
	}

	// Verify proposal censorship records
	for _, p := range upr.Proposals {
		err := verifyProposal(p, vr.PubKey)
		if err != nil {
			return fmt.Errorf("unable to verify proposal %v: %v",
				p.CensorshipRecord.Token, err)
		}
	}

	// Print user proposals
	return shared.PrintJSON(upr)
}

// userProposalsHelpMsg is the output of the help command when 'userproposals'
// is specified.
const userProposalsHelpMsg = `userproposals "userID" 

Fetch all proposals submitted by a specific user.

Arguments:
1. userID      (string, required)   User id

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
  ],
  "numofproposals":  (int)  Number of proposals submitted by user  
}`
