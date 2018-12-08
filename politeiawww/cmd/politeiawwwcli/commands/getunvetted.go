package commands

import (
	"fmt"

	"github.com/decred/politeia/politeiawww/api/v1"
)

// Help message displayed for the command 'politeiawwwcli help getunvetted'
var GetUnvettedCmdHelpMsg = `getunvetted 

Fetch all unvetted proposals. 

Arguments:
1. before      (string, optional)   Get proposals before this proposal (token)
2. after       (string, optional)   Get proposals after this proposal (token)

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

type GetUnvettedCmd struct {
	Before string `long:"before" description:"A proposal censorship token; if provided, the page of proposals returned will end right before the proposal whose token is provided."`
	After  string `long:"after" description:"A proposal censorship token; if provided, the page of proposals returned will begin right after the proposal whose token is provided."`
}

func (cmd *GetUnvettedCmd) Execute(args []string) error {
	if cmd.Before != "" && cmd.After != "" {
		return fmt.Errorf(ErrorBeforeAndAfter)
	}

	// Get server's public key
	vr, err := c.Version()
	if err != nil {
		return err
	}

	// Get all unvetted proposals
	gaur, err := c.GetAllUnvetted(&v1.GetAllUnvetted{
		Before: cmd.Before,
		After:  cmd.After,
	})
	if err != nil {
		return err
	}

	// Verify proposal censorship records
	for _, p := range gaur.Proposals {
		err = VerifyProposal(p, vr.PubKey)
		if err != nil {
			return fmt.Errorf("unable to verify proposal %v: %v",
				p.CensorshipRecord.Token, err)
		}
	}

	// Print unvetted proposals
	return Print(gaur, cfg.Verbose, cfg.RawJSON)
}
