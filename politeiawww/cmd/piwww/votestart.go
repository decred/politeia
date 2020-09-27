// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"encoding/json"
	"strconv"

	"github.com/decred/politeia/decredplugin"
	pi "github.com/decred/politeia/politeiawww/api/pi/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
	"github.com/decred/politeia/util"
)

// voteStartCmd starts the voting period on the specified proposal.
//
// The QuorumPercentage and PassPercentage are strings and not uint32 so that a
// value of 0 can be passed in and not be overwritten by the defaults. This is
// sometimes desirable when testing.
type voteStartCmd struct {
	Args struct {
		Token            string `positional-arg-name:"token" required:"true"`
		Duration         uint32 `positional-arg-name:"duration"`
		QuorumPercentage string `positional-arg-name:"quorumpercentage"`
		PassPercentage   string `positional-arg-name:"passpercentage"`
	} `positional-args:"true"`
}

// Execute executes the start vote command.
func (cmd *voteStartCmd) Execute(args []string) error {
	// Check for user identity
	if cfg.Identity == nil {
		return shared.ErrUserIdentityNotFound
	}

	// Get proposal version. This is needed for the pi route.
	pdr, err := client.ProposalDetails(cmd.Args.Token, nil)
	if err != nil {
		return err
	}
	version, err := strconv.ParseUint(pdr.Proposal.Version, 10, 32)
	if err != nil {
		return err
	}

	// Setup vote params
	var (
		// Default values
		duration uint32 = 2016
		quorum   uint32 = 20
		pass     uint32 = 60
	)
	if cmd.Args.Duration != 0 {
		duration = cmd.Args.Duration
	}
	if cmd.Args.QuorumPercentage != "" {
		i, err := strconv.ParseUint(cmd.Args.QuorumPercentage, 10, 32)
		if err != nil {
			return err
		}
		quorum = uint32(i)
	}
	if cmd.Args.PassPercentage != "" {
		i, err := strconv.ParseUint(cmd.Args.PassPercentage, 10, 32)
		if err != nil {
			return err
		}
		pass = uint32(i)
	}

	// Create VoteStart
	vote := pi.VoteParams{
		Token:            cmd.Args.Token,
		Version:          uint32(version),
		Type:             pi.VoteTypeStandard,
		Mask:             0x03, // bit 0 no, bit 1 yes
		Duration:         duration,
		QuorumPercentage: quorum,
		PassPercentage:   pass,
		Options: []pi.VoteOption{
			{
				ID:          decredplugin.VoteOptionIDApprove,
				Description: "Approve proposal",
				Bit:         0x01,
			},
			{
				ID:          decredplugin.VoteOptionIDReject,
				Description: "Don't approve proposal",
				Bit:         0x02,
			},
		},
	}

	vb, err := json.Marshal(vote)
	if err != nil {
		return err
	}
	msg := hex.EncodeToString(util.Digest(vb))
	sig := cfg.Identity.SignMessage([]byte(msg))
	vs := pi.VoteStart{
		Params:    vote,
		PublicKey: hex.EncodeToString(cfg.Identity.Public.Key[:]),
		Signature: hex.EncodeToString(sig[:]),
	}

	// Print request details
	err = shared.PrintJSON(vs)
	if err != nil {
		return err
	}

	// Send request
	vsr, err := client.VoteStart(vs)
	if err != nil {
		return err
	}

	// Remove ticket snapshot from the response so that the output
	// is legible
	vsr.EligibleTickets = []string{"removed by piwww for readability"}

	// Print response details
	return shared.PrintJSON(vsr)
}

// voteStartHelpMsg is the output of the help command when 'votestart' is
// specified.
var voteStartHelpMsg = `votestart <token> <duration> <quorumpercentage> <passpercentage>

Start voting period for a proposal. Requires admin privileges.

The quorumpercentage and passpercentage are strings and not uint32 so that a
value of 0 can be passed in and not be overwritten by the defaults. This is
sometimes desirable when testing.

Arguments:
1. token              (string, required)  Proposal censorship token
2. duration           (uint32, optional)  Duration of vote in blocks (default: 2016)
3. quorumpercentage   (string, optional)  Percent of votes required for quorum (default: 10)
4. passpercentage     (string, optional)  Percent of votes required to pass (default: 60)
`
