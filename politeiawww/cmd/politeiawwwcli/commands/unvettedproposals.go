// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

import (
	"fmt"

	"github.com/decred/politeia/politeiawww/api/www/v1"
)

// UnvettedProposalsCmd retrieves a page of unvetted proposals.
type UnvettedProposalsCmd struct {
	Before string `long:"before"` // Before censorship token filter
	After  string `long:"after"`  // After censorship token filter
}

// Execute executes the proposals unvetted command.
func (cmd *UnvettedProposalsCmd) Execute(args []string) error {
	if cmd.Before != "" && cmd.After != "" {
		return errInvalidBeforeAfterUsage
	}

	// Get server's public key
	vr, err := client.Version()
	if err != nil {
		return err
	}

	// Get all unvetted proposals
	gaur, err := client.GetAllUnvetted(&v1.GetAllUnvetted{
		Before: cmd.Before,
		After:  cmd.After,
	})
	if err != nil {
		return err
	}

	// Verify proposal censorship records
	for _, p := range gaur.Proposals {
		err = verifyProposal(p, vr.PubKey)
		if err != nil {
			return fmt.Errorf("unable to verify proposal %v: %v",
				p.CensorshipRecord.Token, err)
		}
	}

	// Print unvetted proposals
	return printJSON(gaur)
}

// unvettedProposalsHelpMsg is the output for the help command when
// 'unvettedproposals' is specified.
const unvettedProposalsHelpMsg = `unvettedproposals [flags]

Fetch a page of unvetted proposals. 

Arguments: None

Flags:
  --before     (string, optional)   Get proposals before this proposal (token)
  --after      (string, optional)   Get proposals after this proposal (token)

Example:
getunvetted --after=[token]

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
