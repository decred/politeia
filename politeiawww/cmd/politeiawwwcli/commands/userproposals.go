package commands

import (
	"fmt"

	"github.com/decred/politeia/politeiawww/api/v1"
)

// Help message displayed for the command 'politeiawwwcli help userproposals'
var UserProposalsCmdHelpMsg = `userproposals "userID" 

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

type UserProposalsCmd struct {
	Args struct {
		UserID string `positional-arg-name:"userID"`
	} `positional-args:"true" required:"true"`
}

func (cmd *UserProposalsCmd) Execute(args []string) error {
	// Get server public key
	vr, err := c.Version()
	if err != nil {
		return err
	}

	// Get user proposals
	upr, err := c.UserProposals(&v1.UserProposals{
		UserId: cmd.Args.UserID,
	})
	if err != nil {
		return err
	}

	// Verify proposal censorship records
	for _, p := range upr.Proposals {
		err := VerifyProposal(p, vr.PubKey)
		if err != nil {
			return fmt.Errorf("unable to verify proposal %v: %v",
				p.CensorshipRecord.Token, err)
		}
	}

	// Print user proposals
	return Print(upr, cfg.Verbose, cfg.RawJSON)
}
