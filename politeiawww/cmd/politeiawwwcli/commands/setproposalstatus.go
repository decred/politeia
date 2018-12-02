package commands

import (
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/decred/politeia/politeiawww/api/v1"
)

// Help message displayed for the command 'politeiawwwcli help setproposalstatus'
var SetProposalStatusCmdHelpMsg = `setproposalstatus "token" "status"

Set the status of a proposal (admin).

Arguments:
1. token      (string, required)   Proposal censorship token
2. status     (string, required)   New status (censored, public, abandoned)
3. message    (string, required if censoring proposal)  Status change message

Result:
{
  "token":           (string)  Censorship token
  "proposalstatus":  (PropStatusT)  Proposal status code    
  "signature":       (string)  Signature of proposal status change
  "publickey":       (string)  Public key of user changing proposal status
}
{
  "proposal": {
    "name":          (string)  Suggested short proposal name 
    "state":         (PropStateT)   Current state of proposal
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
    "numcomments":   (uint)  Number of comments on proposal
    "version": 		 (string)  Version of proposal
    "censorshiprecord": {	
      "token":       (string)  Censorship token
      "merkle":      (string)  Merkle root of proposal
      "signature":   (string)  Server side signature of []byte(Merkle+Token)
    }
  }
}`

type SetProposalStatusCmd struct {
	Args struct {
		Token   string `positional-arg-name:"token" required:"true" description:"Proposal censorship record token"`
		Status  string `positional-arg-name:"status" required:"true" description:"New proposal status (censored or public)"`
		Message string `positional-arg-name:"message" description:"Status change message (required if censoring proposal)"`
	} `positional-args:"true"`
}

func (cmd *SetProposalStatusCmd) Execute(args []string) error {
	PropStatus := map[string]v1.PropStatusT{
		"censored":  v1.PropStatusCensored,
		"public":    v1.PropStatusPublic,
		"abandoned": v1.PropStatusAbandoned,
	}

	// Validate user identity
	if cfg.Identity == nil {
		return fmt.Errorf(ErrorNoUserIdentity)
	}

	// Parse proposal status.  This can be either the numeric
	// status code or the human readable equivalent.
	var status v1.PropStatusT
	s, err := strconv.ParseUint(cmd.Args.Status, 10, 32)
	if err == nil {
		// Numeric status code found
		status = v1.PropStatusT(s)
	} else if s, ok := PropStatus[cmd.Args.Status]; ok {
		// Human readable status code found
		status = s
	} else {
		return fmt.Errorf("Invalid proposal status.  Valid statuses are:\n" +
			"  censored    censor a proposal\n" +
			"  public      make a proposal public\n" +
			"  abandoned   declare a public proposal abandoned")
	}

	// Setup request
	sig := cfg.Identity.SignMessage([]byte(cmd.Args.Token +
		strconv.Itoa(int(status)) + cmd.Args.Message))
	sps := &v1.SetProposalStatus{
		Token:               cmd.Args.Token,
		ProposalStatus:      status,
		StatusChangeMessage: cmd.Args.Message,
		Signature:           hex.EncodeToString(sig[:]),
		PublicKey:           hex.EncodeToString(cfg.Identity.Public.Key[:]),
	}

	// Print request details
	err = Print(sps, cfg.Verbose, cfg.RawJSON)
	if err != nil {
		return err
	}

	// Send request
	spsr, err := c.SetProposalStatus(sps)
	if err != nil {
		return err
	}

	// Print response details
	return Print(spsr, cfg.Verbose, cfg.RawJSON)
}
