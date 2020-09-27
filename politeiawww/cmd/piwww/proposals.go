// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"strings"

	pi "github.com/decred/politeia/politeiawww/api/pi/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// proposalsCmd retrieves the proposal records of the requested tokens and versions.
type proposalsCmd struct {
	Args struct {
		Proposals []string `positional-arg-name:"proposals" required:"true"`
	} `positional-args:"true" optional:"true"`

	// Unvetted requests for unvetted proposals instead of vetted ones.
	Unvetted bool `long:"unvetted" optional:"true"`

	// IncludeFiles adds the proposals files to the response payload.
	IncludeFiles bool `long:"includefiles" optional:"true"`
}

// Execute executes the proposals command.
func (cmd *proposalsCmd) Execute(args []string) error {
	proposals := cmd.Args.Proposals

	// Set state to get unvetted or vetted proposals. Defaults
	// to vetted unless the unvetted flag is used.
	var state pi.PropStateT
	switch {
	case cmd.Unvetted:
		state = pi.PropStateUnvetted
	default:
		state = pi.PropStateVetted
	}

	// Build proposals request
	var requests []pi.ProposalRequest
	for _, p := range proposals {
		// Parse token and version
		var r pi.ProposalRequest
		tokenAndVersion := strings.Split(p, ",")
		switch len(tokenAndVersion) {
		case 1:
			// No version provided
			r.Token = tokenAndVersion[0]
		case 2:
			// Version provided
			r.Token = tokenAndVersion[0]
			r.Version = tokenAndVersion[1]
		default:
			return fmt.Errorf("invalid format for proposal request. check " +
				"the help command for usage example")
		}

		requests = append(requests, r)
	}

	// Setup and send request
	props := pi.Proposals{
		State:        state,
		Requests:     requests,
		IncludeFiles: cmd.IncludeFiles,
	}

	reply, err := client.Proposals(props)
	if err != nil {
		return err
	}

	return shared.PrintJSON(reply)
}

// proposalsHelpMsg is the output of the help command.
const proposalsHelpMsg = `proposals [flags] "proposals" 

Fetch the proposal record for the requested tokens in "proposals". A request
is set by providing the censorship record token and the desired version, 
comma-separated. Providing only the token will default to the latest proposal
version.

Arguments:
1. proposals ([]string, required) Proposals request

Flags:
 --unvetted     (bool, optional) Request for unvetted proposals instead of
                                 vetted ones.
 --includefiles (bool, optional) Include proposal files in the returned
                                 proposal records.

Example:
 piwww proposals <token,version> <token,version> ...
`
