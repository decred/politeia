// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	tkv1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
	"github.com/decred/politeia/politeiawww/cmd/shared"
	"github.com/decred/politeia/util"
)

// cmdVoteStart starts the voting period on a record.
//
// QuorumPercentage and PassPercentage are strings and not uint32 so that a
// value of 0 can be passed in and not be overwritten by the defaults. This is
// sometimes desirable when testing.
type cmdVoteStart struct {
	Args struct {
		Token            string `positional-arg-name:"token" required:"true"`
		Duration         uint32 `positional-arg-name:"duration"`
		QuorumPercentage uint32 `positional-arg-name:"quorumpercentage"`
		PassPercentage   uint32 `positional-arg-name:"passpercentage"`
	} `positional-args:"true"`

	// Runoff is used to indicate the vote is a runoff vote and the
	// provided token is the parent token of the runoff vote.
	Runoff bool `long:"runoff" optional:"true"`
}

func voteStartStandard(token string, duration, quorum, pass uint32, pc *pclient.Client) (*tkv1.StartReply, error) {
	// Get record version
	d := rcv1.Details{
		State: rcv1.RecordStateVetted,
		Token: token,
	}
	r, err := pc.RecordDetails(d)
	if err != nil {
		return nil, err
	}
	version, err := strconv.ParseUint(r.Version, 10, 64)
	if err != nil {
		return nil, err
	}

	// Setup request
	vp := tkv1.VoteParams{
		Token:            token,
		Version:          uint32(version),
		Type:             tkv1.VoteTypeStandard,
		Mask:             0x03,
		Duration:         duration,
		QuorumPercentage: quorum,
		PassPercentage:   pass,
		Options: []tkv1.VoteOption{
			{
				ID:          tkv1.VoteOptionIDApprove,
				Description: "Approve the proposal",
				Bit:         0x01,
			},
			{
				ID:          tkv1.VoteOptionIDReject,
				Description: "Reject the proposal",
				Bit:         0x02,
			},
		},
	}
	vpb, err := json.Marshal(vp)
	if err != nil {
		return nil, err
	}
	msg := hex.EncodeToString(util.Digest(vpb))
	b := cfg.Identity.SignMessage([]byte(msg))
	signature := hex.EncodeToString(b[:])
	s := tkv1.Start{
		Starts: []tkv1.StartDetails{
			{
				Params:    vp,
				PublicKey: cfg.Identity.Public.String(),
				Signature: signature,
			},
		},
	}

	// Send request
	return pc.TicketVoteStart(s)
}

func voteStartRunoff(parentToken string, duration, quorum, pass uint32, pc *pclient.Client) (*tkv1.StartReply, error) {
	// Get runoff vote submissions
	lf := tkv1.LinkedFrom{
		Tokens: []string{parentToken},
	}
	lfr, err := pc.TicketVoteLinkedFrom(lf)
	if err != nil {
		return nil, fmt.Errorf("TicketVoteLinkedFrom: %v", err)
	}
	linkedFrom, ok := lfr.LinkedFrom[parentToken]
	if !ok {
		return nil, fmt.Errorf("linked from not found %v", parentToken)
	}

	// Prepare start details for each submission
	starts := make([]tkv1.StartDetails, 0, len(linkedFrom))
	for _, v := range linkedFrom {
		// Get record
		d := rcv1.Details{
			State: rcv1.RecordStateVetted,
			Token: v,
		}
		r, err := pc.RecordDetails(d)
		if err != nil {
			return nil, fmt.Errorf("RecordDetails %v: %v", v, err)
		}
		version, err := strconv.ParseUint(r.Version, 10, 64)
		if err != nil {
			return nil, err
		}

		// Don't include the record if it has been abandoned.
		if r.Status == rcv1.RecordStatusArchived {
			continue
		}

		// Setup vote params
		vp := tkv1.VoteParams{
			Token:            r.CensorshipRecord.Token,
			Version:          uint32(version),
			Type:             tkv1.VoteTypeRunoff,
			Mask:             0x03, // bit 0 no, bit 1 yes
			Duration:         duration,
			QuorumPercentage: quorum,
			PassPercentage:   pass,
			Options: []tkv1.VoteOption{
				{
					ID:          ticketvote.VoteOptionIDApprove,
					Description: "Approve the proposal",
					Bit:         0x01,
				},
				{
					ID:          ticketvote.VoteOptionIDReject,
					Description: "Reject the proposal",
					Bit:         0x02,
				},
			},
			Parent: parentToken,
		}
		vpb, err := json.Marshal(vp)
		if err != nil {
			return nil, err
		}
		msg := hex.EncodeToString(util.Digest(vpb))
		sig := cfg.Identity.SignMessage([]byte(msg))
		starts = append(starts, tkv1.StartDetails{
			Params:    vp,
			PublicKey: cfg.Identity.Public.String(),
			Signature: hex.EncodeToString(sig[:]),
		})
	}

	// Send request
	s := tkv1.Start{
		Starts: starts,
	}
	return pc.TicketVoteStart(s)
}

// Execute executes the cmdVoteStart command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdVoteStart) Execute(args []string) error {
	token := c.Args.Token

	// Verify user identity. An identity is required to sign the vote
	// start.
	if cfg.Identity == nil {
		return shared.ErrUserIdentityNotFound
	}

	// Setup client
	opts := pclient.Opts{
		HTTPSCert:  cfg.HTTPSCert,
		Cookies:    cfg.Cookies,
		HeaderCSRF: cfg.CSRF,
		Verbose:    cfg.Verbose,
		RawJSON:    cfg.RawJSON,
	}
	pc, err := pclient.New(cfg.Host, opts)
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
	if c.Args.Duration != 0 {
		duration = c.Args.Duration
	}
	if c.Args.QuorumPercentage != 0 {
		quorum = c.Args.QuorumPercentage
	}
	if c.Args.PassPercentage != 0 {
		pass = c.Args.PassPercentage
	}

	var sr *tkv1.StartReply
	if c.Runoff {
		sr, err = voteStartRunoff(token, duration, quorum, pass, pc)
		if err != nil {
			return err
		}
	} else {
		sr, err = voteStartStandard(token, duration, quorum, pass, pc)
		if err != nil {
			return err
		}
	}

	// Print reply
	printf("StartBlockHash  : %v\n", sr.StartBlockHash)
	printf("StartBlockHeight: %v\n", sr.StartBlockHeight)
	printf("EndBlockHeight  : %v\n", sr.EndBlockHeight)

	return nil
}

// voteStartHelpMsg is printed to stdout by the help command.
var voteStartHelpMsg = `votestart <token> <duration> <quorumpercentage> <passpercentage>

Start the voting period for a proposal. Requires admin privileges.

If the vote is a runoff vote then the --runoff flag must be used. The provided
token should be the parent token of the runoff vote.

Arguments:
1. token             (string, required)  Proposal censorship token
2. duration          (uint32, optional)  Duration of vote in blocks
                                         (default: 2016)
3. quorumpercentage  (uint32, optional)  Percent of total votes required to
                                         reach a quorum (default: 10)
4. passpercentage    (uint32, optional)  Percent of cast votes required for
                                         vote to be approved (default: 60)
Flags:
 --runoff  (bool, optional)  Start a runoff vote.
`
