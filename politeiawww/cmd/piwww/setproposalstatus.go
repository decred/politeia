// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/thi4go/politeia/politeiawww/api/www/v1"
	"github.com/thi4go/politeia/politeiawww/cmd/shared"
)

// SetProposalStatusCmd sets the status of a proposal.
type SetProposalStatusCmd struct {
	Args struct {
		Token   string `positional-arg-name:"token" required:"true"`  // Censorship token
		Status  string `positional-arg-name:"status" required:"true"` // New status
		Message string `positional-arg-name:"message"`                // Change message
	} `positional-args:"true"`
}

// Execute executes the set proposal status command.
func (cmd *SetProposalStatusCmd) Execute(args []string) error {
	PropStatus := map[string]v1.PropStatusT{
		"censored":  v1.PropStatusCensored,
		"public":    v1.PropStatusPublic,
		"abandoned": v1.PropStatusAbandoned,
	}

	// Validate user identity
	if cfg.Identity == nil {
		return shared.ErrUserIdentityNotFound
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
		return fmt.Errorf("Invalid proposal status '%v'.  "+
			"Valid statuses are:\n"+
			"  censored    censor a proposal\n"+
			"  public      make a proposal public\n"+
			"  abandoned   declare a public proposal abandoned",
			cmd.Args.Status)
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
	err = shared.PrintJSON(sps)
	if err != nil {
		return err
	}

	// Send request
	spsr, err := client.SetProposalStatus(sps)
	if err != nil {
		return err
	}

	// Print response details
	return shared.PrintJSON(spsr)
}

// setProposalStatusHelpMsg is the output of the help command when
// "setproposalstatus" is specified.
const setProposalStatusHelpMsg = `setproposalstatus "token" "status"

Set the status of a proposal. Requires admin privileges.

Arguments:
1. token      (string, required)   Proposal censorship token
2. status     (string, required)   New status (censored, public, abandoned)
3. message    (string, required if censoring proposal)  Status change message

Request:
{
  "token":           (string)  Censorship token
  "proposalstatus":  (PropStatusT)  Proposal status code    
  "signature":       (string)  Signature of proposal status change
  "publickey":       (string)  Public key of user changing proposal status
}

Response:
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
