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

// proposalStatusSetCmd sets the status of a proposal.
type proposalStatusSetCmd struct {
	Args struct {
		Token   string `positional-arg-name:"token" required:"true"`
		Status  string `positional-arg-name:"status" required:"true"`
		Reason  string `positional-arg-name:"reason"`
		Version string `positional-arg-name:"version"`
	} `positional-args:"true"`

	Unvetted bool `long:"unvetted" optional:"true"`
}

// Execute executes the set proposal status command.
func (cmd *proposalStatusSetCmd) Execute(args []string) error {
	propStatus := map[string]pi.PropStatusT{
		"public":    pi.PropStatusPublic,
		"censored":  pi.PropStatusCensored,
		"abandoned": pi.PropStatusAbandoned,
	}

	// Verify state. Defaults to vetted if the --unvetted flag
	// is not used.
	var state pi.PropStateT
	switch {
	case cmd.Unvetted:
		state = pi.PropStateUnvetted
	default:
		state = pi.PropStateVetted
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
		return fmt.Errorf("Invalid proposal status '%v'\n %v",
			cmd.Args.Status, proposalStatusSetHelpMsg)
	}

	// Verify version
	var version string
	if cmd.Args.Version != "" {
		version = cmd.Args.Version
	} else {
		// Get the version manually
		pr, err := proposalRecordLatest(state, cmd.Args.Token)
		if err != nil {
			return err
		}
		version = pr.Version
	}

	// Setup request
	msg := cmd.Args.Token + version + strconv.Itoa(int(status)) + cmd.Args.Reason
	sig := cfg.Identity.SignMessage([]byte(msg))
	pss := pi.ProposalStatusSet{
		Token:     cmd.Args.Token,
		State:     state,
		Version:   version,
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
	pssr, err := client.ProposalStatusSet(pss)
	if err != nil {
		return err
	}
	err = shared.PrintJSON(pssr)
	if err != nil {
		return err
	}

	return nil
}

// proposalStatusSetHelpMsg is the output of the help command.
const proposalStatusSetHelpMsg = `proposalstatusset "token" "status" "reason"

Set the status of a proposal. This command assumes the proposal is a vetted
record. If the proposal is unvetted, the --unvetted flag must be used. Requires
admin priviledges.

Valid statuses:
  public
  censored
  abandoned

Arguments:
1. token   (string, required)  Proposal censorship token
2. status  (string, required)  New status
3. message (string, optional)  Status change message
4. version (string, optional)  Proposal version. This will be fetched manually
                               if one is not provided.

Flags:
  --unvetted (bool, optional)    Set status of an unvetted record.
`
