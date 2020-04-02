// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/thi4go/politeia/politeiawww/api/www/v1"
	"github.com/thi4go/politeia/politeiawww/cmd/shared"
)

// VettedProposalsCmd retreives a page of vetted proposals.
type VettedProposalsCmd struct {
	Before string `long:"before"` // Before censorship token
	After  string `long:"after"`  // After censorship token
}

// Execute executs the vetted proposals command.
func (cmd *VettedProposalsCmd) Execute(args []string) error {
	if cmd.Before != "" && cmd.After != "" {
		return fmt.Errorf("the 'before' and 'after' flags " +
			"cannot be used at the same time")
	}

	// Get server's public key
	vr, err := client.Version()
	if err != nil {
		return err
	}

	// Get a page of vetted proposals
	gavr, err := client.GetAllVetted(&v1.GetAllVetted{
		Before: cmd.Before,
		After:  cmd.After,
	})
	if err != nil {
		return err
	}

	// Verify proposal censorship records
	for _, p := range gavr.Proposals {
		err = verifyProposal(p, vr.PubKey)
		if err != nil {
			return fmt.Errorf("unable to verify proposal %v: %v",
				p.CensorshipRecord.Token, err)
		}
	}

	// Print vetted proposals
	return shared.PrintJSON(gavr)
}

// vettedproposalsHelpMsg is the output for the help command when
// 'vettedproposals' is specified.
const vettedProposalsHelpMsg = `vettedproposals [flags]

Fetch a page of vetted proposals. 

Arguments: None

Flags:
  --before     (string, optional)   Get proposals before this proposal (token)
  --after      (string, optional)   Get proposals after this proposal (token)

Example:
getvetted --after=[token]

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
  ]
}`
