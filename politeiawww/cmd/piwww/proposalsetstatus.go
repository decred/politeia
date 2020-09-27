// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"fmt"
	"strconv"

	pi "github.com/decred/politeia/politeiawww/api/pi/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// proposalSetStatusCmd sets the status of a proposal.
type proposalSetStatusCmd struct {
	Args struct {
		Token  string `positional-arg-name:"token" required:"true"`
		Status string `positional-arg-name:"status" required:"true"`
		Reason string `positional-arg-name:"reason"`
	} `positional-args:"true"`
	Vetted   bool `long:"vetted" optional:"true"`
	Unvetted bool `long:"unvetted" optional:"true"`
}

// Execute executes the set proposal status command.
func (cmd *proposalSetStatusCmd) Execute(args []string) error {
	propStatus := map[string]pi.PropStatusT{
		"public":    pi.PropStatusPublic,
		"censored":  pi.PropStatusCensored,
		"abandoned": pi.PropStatusAbandoned,
	}

	// Verify state
	var state pi.PropStateT
	switch {
	case cmd.Vetted && cmd.Unvetted:
		return fmt.Errorf("cannot use --vetted and --unvetted simultaneously")
	case cmd.Unvetted:
		state = pi.PropStateUnvetted
	case cmd.Vetted:
		state = pi.PropStateVetted
	default:
		return fmt.Errorf("must specify either --vetted or unvetted")
	}

	// Validate user identity
	if cfg.Identity == nil {
		return shared.ErrUserIdentityNotFound
	}

	// Parse proposal status. This can be either the numeric status
	// code or the human readable equivalent.
	var status pi.PropStatusT
	s, err := strconv.ParseUint(cmd.Args.Status, 10, 32)
	if err == nil {
		// Numeric status code found
		status = pi.PropStatusT(s)
	} else if s, ok := propStatus[cmd.Args.Status]; ok {
		// Human readable status code found
		status = s
	} else {
		return fmt.Errorf("Invalid proposal status '%v'. Valid statuses are:\n"+
			"  public      make a proposal public\n"+
			"  censored    censor a proposal\n"+
			"  abandoned   declare a public proposal abandoned",
			cmd.Args.Status)
	}

	// Get the proposal. The latest proposal version number is needed
	// for the set status request.
	pr, err := proposalRecordLatest(state, cmd.Args.Token)
	if err != nil {
		return err
	}

	// Setup request
	msg := cmd.Args.Token + pr.Version + cmd.Args.Status + cmd.Args.Reason
	sig := cfg.Identity.SignMessage([]byte(msg))
	pss := pi.ProposalSetStatus{
		Token:     cmd.Args.Token,
		State:     state,
		Version:   pr.Version,
		Status:    status,
		Reason:    cmd.Args.Reason,
		Signature: hex.EncodeToString(sig[:]),
		PublicKey: hex.EncodeToString(cfg.Identity.Public.Key[:]),
	}

	// Send request. The request and response details are printed to
	// the console based on the logging flags that were used.
	err = shared.PrintJSON(pss)
	if err != nil {
		return err
	}
	pssr, err := client.ProposalSetStatus(pss)
	if err != nil {
		return err
	}
	err = shared.PrintJSON(pssr)
	if err != nil {
		return err
	}

	return nil
}

// proposalSetStatusHelpMsg is the output of the help command.
const proposalSetStatusHelpMsg = `proposalsetstatus "token" "status" "reason"

Set the status of a proposal. Requires admin privileges.

Valid statuses:
  public
  censored
  abandoned

Arguments:
1. token   (string, required)    Proposal censorship token
2. status  (string, required)    New status
3. message (string, optional)    Status change message

Flags:
  --vetted   (bool, optional)    Set status of a vetted record.
  --unvetted (bool, optional)    Set status of an unvetted reocrd.
`
