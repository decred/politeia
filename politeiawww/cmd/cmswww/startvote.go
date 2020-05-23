// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"encoding/json"

	v1 "github.com/decred/politeia/politeiawww/api/cms/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
	"github.com/decred/politeia/util"
)

// StartVoteCmd starts the voting period on the specified proposal.
type StartVoteCmd struct {
	Args struct {
		Token            string `positional-arg-name:"token" required:"true"`
		Duration         uint32 `positional-arg-name:"duration"`
		QuorumPercentage uint32 `positional-arg-name:"quorumpercentage"`
		PassPercentage   uint32 `positional-arg-name:"passpercentage"`
	} `positional-args:"true"`
}

// Execute executes the start vote command.
func (cmd *StartVoteCmd) Execute(args []string) error {
	// Check for user identity
	if cfg.Identity == nil {
		return shared.ErrUserIdentityNotFound
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
	if cmd.Args.QuorumPercentage != 0 {
		quorum = cmd.Args.QuorumPercentage
	}
	if cmd.Args.PassPercentage != 0 {
		pass = cmd.Args.PassPercentage
	}

	// Create StartVote
	vote := v1.Vote{
		Token:            cmd.Args.Token,
		Mask:             0x03, // bit 0 no, bit 1 yes
		Duration:         duration,
		QuorumPercentage: quorum,
		PassPercentage:   pass,
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
	}
	vb, err := json.Marshal(vote)
	if err != nil {
		return err
	}
	msg := hex.EncodeToString(util.Digest(vb))
	sig := cfg.Identity.SignMessage([]byte(msg))
	sv := v1.StartVote{
		Vote:      vote,
		PublicKey: hex.EncodeToString(cfg.Identity.Public.Key[:]),
		Signature: hex.EncodeToString(sig[:]),
	}

	// Print request details
	err = shared.PrintJSON(sv)
	if err != nil {
		return err
	}

	// Send request
	svr, err := client.StartVoteDCC(sv)
	if err != nil {
		return err
	}

	// Remove ticket snapshot from the response so that the output
	// is legible
	svr.UserWeights = []string{"removed by piwww for readability"}

	// Print response details
	return shared.PrintJSON(svr)
}

// startVoteHelpMsg is the output of the help command when 'startvote' is
// specified.
var startVoteHelpMsg = `startvote <token> <duration> <quorumpercentage> <passpercentage>

Start voting period for a dcc. Requires admin privileges.  The optional
arguments must either all be used or none be used.

Arguments:
1. token              (string, required)  Proposal censorship token
2. duration           (uint32, optional)  Duration of vote in blocks (default: 2016)
3. quorumpercentage   (uint32, optional)  Percent of votes required for quorum (default: 10)
4. passpercentage     (uint32, optional)  Percent of votes required to pass (default: 60)

Result:

{
  "startblockheight"     (string)    Block height at start of vote
  "startblockhash"       (string)    Hash of first block of vote interval
  "endheight"            (string)    Height of vote end
  "userweights"          ([]string)  Valid voting users and their weights   
}`
