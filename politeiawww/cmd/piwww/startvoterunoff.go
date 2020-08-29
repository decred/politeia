// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"encoding/json"
	"strconv"

	"github.com/decred/politeia/decredplugin"
	v1 "github.com/decred/politeia/politeiawww/api/www/v1"
	v2 "github.com/decred/politeia/politeiawww/api/www/v2"
	"github.com/decred/politeia/politeiawww/cmd/shared"
	"github.com/decred/politeia/util"
)

// StartVoteRunoffCmd starts the voting period on all public submissions to a
// request for proposals (RFP).
//
// The QuorumPercentage and PassPercentage are strings and not uint32 so that a
// value of 0 can be passed in and not be overwritten by the defaults. This is
// sometimes desirable when testing.
type StartVoteRunoffCmd struct {
	Args struct {
		TokenRFP         string `positional-arg-name:"token" required:"true"` // RFP censorship token
		Duration         uint32 `positional-arg-name:"duration"`              // Duration in blocks
		QuorumPercentage string `positional-arg-name:"quorumpercentage"`
		PassPercentage   string `positional-arg-name:"passpercentage"`
	} `positional-args:"true"`
}

// Execute executes the StartVoteRunoff command.
func (cmd *StartVoteRunoffCmd) Execute(args []string) error {
	// Check for user identity
	if cfg.Identity == nil {
		return shared.ErrUserIdentityNotFound
	}

	// Setup vote params
	var (
		// Default values
		duration uint32 = 2016
		quorum   uint32 = 10
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

	// Fetch RFP proposal and RFP submissions
	pdr, err := client.ProposalDetails(cmd.Args.TokenRFP,
		&v1.ProposalsDetails{})
	if err != nil {
		return err
	}
	bpr, err := client.BatchProposals(&v1.BatchProposals{
		Tokens: pdr.Proposal.LinkedFrom,
	})
	if err != nil {
		return err
	}

	// Only include submissions that are public. This will
	// filter out any submissions that have been abandoned.
	submissions := make([]v1.ProposalRecord, 0, len(bpr.Proposals))
	for _, v := range bpr.Proposals {
		if v.Status == v1.PropStatusPublic {
			submissions = append(submissions, v)
		}
	}

	// Prepare AuthorizeVote for each submission
	authVotes := make([]v2.AuthorizeVote, 0, len(submissions))
	for _, v := range submissions {
		action := v2.AuthVoteActionAuthorize
		msg := v.CensorshipRecord.Token + v.Version + action
		sig := cfg.Identity.SignMessage([]byte(msg))
		authVotes = append(authVotes, v2.AuthorizeVote{
			Token:     v.CensorshipRecord.Token,
			Action:    action,
			PublicKey: hex.EncodeToString(cfg.Identity.Public.Key[:]),
			Signature: hex.EncodeToString(sig[:]),
		})
	}

	// Prepare StartVote for each submission
	startVotes := make([]v2.StartVote, 0, len(submissions))
	for _, v := range submissions {
		version, err := strconv.ParseUint(v.Version, 10, 32)
		if err != nil {
			return err
		}

		vote := v2.Vote{
			Token:            v.CensorshipRecord.Token,
			ProposalVersion:  uint32(version),
			Type:             v2.VoteTypeRunoff,
			Mask:             0x03, // bit 0 no, bit 1 yes
			Duration:         duration,
			QuorumPercentage: quorum,
			PassPercentage:   pass,
			Options: []v2.VoteOption{
				{
					Id:          decredplugin.VoteOptionIDApprove,
					Description: "Approve proposal",
					Bits:        0x01,
				},
				{
					Id:          decredplugin.VoteOptionIDReject,
					Description: "Don't approve proposal",
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

		startVotes = append(startVotes, v2.StartVote{
			Vote:      vote,
			PublicKey: hex.EncodeToString(cfg.Identity.Public.Key[:]),
			Signature: hex.EncodeToString(sig[:]),
		})
	}

	// Prepare and send request
	svr := v2.StartVoteRunoff{
		Token:          cmd.Args.TokenRFP,
		AuthorizeVotes: authVotes,
		StartVotes:     startVotes,
	}
	err = shared.PrintJSON(svr)
	if err != nil {
		return err
	}
	svrr, err := client.StartVoteRunoffV2(svr)
	if err != nil {
		return err
	}

	// Print response details. Remove ticket snapshot from
	// the response before printing so that the output is
	// legible.
	m := "removed by politeiawwwcli for readability"
	svrr.EligibleTickets = []string{m}
	err = shared.PrintJSON(svrr)
	if err != nil {
		return err
	}

	return nil
}

// startVoteRunoffHelpMsg is the help command output for 'startvoterunoff'.
var startVoteRunoffHelpMsg = `startvoterunoff <token> <duration> <quorumpercentage> <passpercentage>

Start the voting period on all public submissions to an RFP proposal. The
optional arguments must either all be used or none be used.

The quorumpercentage and passpercentage are strings and not uint32 so that a
value of 0 can be passed in and not be overwritten by the defaults. This is
sometimes desirable when testing.

Arguments:
1. token              (string, required)  Proposal censorship token
2. duration           (uint32, optional)  Duration of vote in blocks (default: 2016)
3. quorumpercentage   (uint32, optional)  Percent of votes required for quorum (default: 10)
4. passpercentage     (uint32, optional)  Percent of votes required to pass (default: 60)
`
