// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// StartVoteCmd starts the voting period on the specified proposal.
type StartVoteCmd struct {
	Args struct {
		Token            string `positional-arg-name:"token" required:"true"` // Censorship token
		Duration         string `positional-arg-name:"duration"`              // Vote duration
		QuorumPercentage string `positional-arg-name:"quorumpercentage"`      // Quorum percentage
		PassPercentage   string `positional-arg-name:"passpercentage"`        // Pass percentage
	} `positional-args:"true"`
}

// Execute executes the start vote command.
func (cmd *StartVoteCmd) Execute(args []string) error {
	// Check for user identity
	if cfg.Identity == nil {
		return shared.ErrUserIdentityNotFound
	}

	// Set vote parameter defaults
	if cmd.Args.Duration == "" {
		cmd.Args.Duration = "2016"
	}
	if cmd.Args.QuorumPercentage == "" {
		cmd.Args.QuorumPercentage = "10"
	}
	if cmd.Args.PassPercentage == "" {
		cmd.Args.PassPercentage = "75"
	}

	// Convert vote parameters
	duration, err := strconv.ParseUint(cmd.Args.Duration, 10, 32)
	if err != nil {
		return fmt.Errorf("parsing Duration: %v", err)
	}
	quorum, err := strconv.ParseUint(cmd.Args.QuorumPercentage, 10, 32)
	if err != nil {
		return fmt.Errorf("parsing QuorumPercentage: %v", err)
	}
	pass, err := strconv.ParseUint(cmd.Args.PassPercentage, 10, 32)
	if err != nil {
		return fmt.Errorf("parsing PassPercentage: %v", err)
	}

	// Setup start vote request
	sig := cfg.Identity.SignMessage([]byte(cmd.Args.Token))
	sv := &v1.StartVote{
		Signature: hex.EncodeToString(sig[:]),
		PublicKey: hex.EncodeToString(cfg.Identity.Public.Key[:]),
		Vote: v1.Vote{
			Token:            cmd.Args.Token,
			Mask:             0x03, // bit 0 no, bit 1 yes
			Duration:         uint32(duration),
			QuorumPercentage: uint32(quorum),
			PassPercentage:   uint32(pass),
			Options: []v1.VoteOption{
				{
					Id:          "no",
					Description: "Don't approve proposal",
					Bits:        0x01,
				},
				{
					Id:          "yes",
					Description: "Approve proposal",
					Bits:        0x02,
				},
			},
		},
	}

	// Print request details
	err = shared.PrintJSON(sv)
	if err != nil {
		return err
	}

	// Send request
	svr, err := client.StartVote(sv)
	if err != nil {
		return err
	}

	// Remove ticket snapshot from the response so that the output
	// is legible
	svr.EligibleTickets = []string{"removed by politeiawwwcli for readability"}

	// Print response details
	return shared.PrintJSON(svr)
}

// startVoteHelpMsg is the output of the help command when 'startvote' is
// specified.
var startVoteHelpMsg = `startvote "token" "duration" "quorumpercentage" "passpercentage"

Start voting period for a proposal. Requires admin privileges.  The optional
arguments must either all be used or none be used.

Arguments:
1. token              (string, required)  Proposal censorship token
2. duration           (string, optional)  Duration of vote in blocks
3. quorumpercentage   (string, optional)  Percent of votes required for quorum
4. passpercentage     (string, optional)  Percent of votes required to pass

Result:

{
  "startblockheight"     (string)    Block height at start of vote
  "startblockhash"       (string)    Hash of first block of vote interval
  "endheight"            (string)    Height of vote end
  "eligibletickets"      ([]string)  Valid voting tickets   
}`
