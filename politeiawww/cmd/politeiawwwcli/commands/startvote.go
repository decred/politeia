// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

import (
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/decred/politeia/politeiawww/api/v1"
)

// Help message displayed for the command 'politeiawwwcli help startvote'
var StartVoteCmdHelpMsg = `startvote "token" "duration" "quorumpercentage" "passpercentage"

Start voting period for a proposal. Requires admin privileges.

Arguments:
1. token              (string, required)  Proposal censorship token
1. duration           (uint32, optional)  Duration of vote in blocks
2. quorumpercentage   (uint32, optional)  Percent of votes required for quorum
3. passpercentage     (uint32, optional)  Percent of votes required to pass

Result:

{
  "startblockheight"     (string)    Block height at start of vote
  "startblockhash"       (string)    Hash of first block of vote interval
  "endheight"            (string)    Height of vote end
  "eligibletickets"      ([]string)  Valid voting tickets   
}`

type StartVoteCmd struct {
	Args struct {
		Token string `positional-arg-name:"token" description:"Proposal censorship token"`
	} `positional-args:"true" required:"true"`
	Duration         string `long:"duration" description:"Vote duration in blocks"`
	QuorumPercentage string `long:"quorumpercentage" description:"Percentage of eligible tickets required for quorum (0-100)"`
	PassPercentage   string `long:"passpercentage" description:"Percentage of votes required for vote to pass (0-100)"`
}

func (cmd *StartVoteCmd) Execute(args []string) error {
	// Check for user identity
	if cfg.Identity == nil {
		return fmt.Errorf(ErrorNoUserIdentity)
	}

	// Set vote parameter defaults
	if cmd.Duration == "" {
		cmd.Duration = "2016"
	}
	if cmd.QuorumPercentage == "" {
		cmd.QuorumPercentage = "10"
	}
	if cmd.PassPercentage == "" {
		cmd.PassPercentage = "75"
	}

	// Convert vote parameters
	duration, err := strconv.ParseUint(cmd.Duration, 10, 32)
	if err != nil {
		return fmt.Errorf("parsing Duration: %v", err)
	}
	quorum, err := strconv.ParseUint(cmd.QuorumPercentage, 10, 32)
	if err != nil {
		return fmt.Errorf("parsing QuorumPercentage: %v", err)
	}
	pass, err := strconv.ParseUint(cmd.PassPercentage, 10, 32)
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
	err = Print(sv, cfg.Verbose, cfg.RawJSON)
	if err != nil {
		return err
	}

	// Send request
	svr, err := c.StartVote(sv)
	if err != nil {
		return err
	}

	// Print response details.  Remove eligible tickets from
	// StartVoteReply so that the output is legible.
	svr.EligibleTickets = []string{"removed by politeiawwwcli for readability"}
	return Print(svr, cfg.Verbose, cfg.RawJSON)
}
