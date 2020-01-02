// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/base64"
	"fmt"

	"github.com/decred/politeia/decredplugin"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// VoteDetailsCmd fetches the vote parameters and vote options from the
// politeiawww v2 VoteDetails routes.
type VoteDetailsCmd struct {
	Args struct {
		Token string `positional-arg-name:"token"` // Proposal token
	} `positional-args:"true" required:"true"`
}

// Execute executes the vote details command.
func (cmd *VoteDetailsCmd) Execute(args []string) error {
	vdr, err := client.VoteDetailsV2(cmd.Args.Token)
	if err != nil {
		return err
	}

	// Remove eligible tickets snapshot from the response
	// so that the output is legible.
	if !cfg.RawJSON {
		vdr.EligibleTickets = []string{
			"removed by piwww for readability",
		}
	}

	err = shared.PrintJSON(vdr)
	if err != nil {
		return err
	}

	// Print the decoded Vote struct
	if !cfg.RawJSON {
		fmt.Printf("decoded vote:\n")
		switch vdr.Version {
		case 1:
			vb, err := base64.StdEncoding.DecodeString(vdr.Vote)
			if err != nil {
				return err
			}
			v, err := decredplugin.DecodeVoteV1(vb)
			if err != nil {
				return err
			}
			err = shared.PrintJSON(v)
			if err != nil {
				return err
			}
		case 2:
			vb, err := base64.StdEncoding.DecodeString(vdr.Vote)
			if err != nil {
				return err
			}
			v, err := decredplugin.DecodeVoteV2(vb)
			if err != nil {
				return err
			}
			err = shared.PrintJSON(v)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("invalid vote version")
		}
	}

	return nil
}

// voteDetailsHelpMsg is the output of the help command when 'votedetails' is
// specified.
const voteDetailsHelpMsg = `votedetails "token"

Fetch the vote details for a proposal.

Arguments:
1. token    (string, required)  Proposal censorship token
`
