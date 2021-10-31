// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	tkv1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
	"github.com/decred/politeia/politeiawww/cmd/shared"
	"github.com/decred/politeia/util"
)

// cmdVoteStart starts the voting period on a record.
type cmdVoteStart struct {
	Args struct {
		Token string `positional-arg-name:"token"`
	} `positional-args:"true"  required:"true"`

	// Duration is the duration, in blocks of the DCR ticket vote.
	Duration uint32 `long:"duration"`

	// Quorum is the percent of total votes required for a quorum. This is a
	// pointer so that a value of 0 can be provided. A quorum of zero allows
	// for the vote to be approved or rejected using a single DCR ticket.
	Quorum *uint32 `long:"quorum"`

	// Passing is the percent of cast votes required for a vote options to be
	// considered as passing.
	Passing uint32 `long:"passing"`

	// Runoff is used to indicate the vote is a runoff vote and the
	// provided token is the parent token of the runoff vote.
	Runoff bool `long:"runoff"`
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

	// Setup the vote params. The default values
	// are overridden if CLI flags are provided.
	var (
		duration = defaultDuration
		quorum   = defaultQuorum
		passing  = defaultPassing
	)
	if c.Duration > 0 {
		duration = c.Duration
	}
	if c.Quorum != nil {
		quorum = *c.Quorum
	}
	if c.Passing != 0 {
		passing = c.Passing
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

	// Start the voting period
	var sr *tkv1.StartReply
	if c.Runoff {
		sr, err = voteStartRunoff(token, duration, quorum, passing, pc)
		if err != nil {
			return err
		}
	} else {
		sr, err = voteStartStandard(token, duration, quorum, passing, pc)
		if err != nil {
			return err
		}
	}

	// Print reply
	printf("Receipt         : %v\n", sr.Receipt)
	printf("StartBlockHash  : %v\n", sr.StartBlockHash)
	printf("StartBlockHeight: %v\n", sr.StartBlockHeight)
	printf("EndBlockHeight  : %v\n", sr.EndBlockHeight)

	return nil
}

func voteStartStandard(token string, duration, quorum, pass uint32, pc *pclient.Client) (*tkv1.StartReply, error) {
	// Get record version
	d := rcv1.Details{
		Token: token,
	}
	r, err := pc.RecordDetails(d)
	if err != nil {
		return nil, err
	}

	// Setup request
	vp := tkv1.VoteParams{
		Token:            token,
		Version:          r.Version,
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
	s := tkv1.Submissions{
		Token: parentToken,
	}
	sr, err := pc.TicketVoteSubmissions(s)
	if err != nil {
		return nil, fmt.Errorf("TicketVoteSubmissions: %v", err)
	}

	// Prepare start details for each submission
	starts := make([]tkv1.StartDetails, 0, len(sr.Submissions))
	for _, v := range sr.Submissions {
		// Get record
		d := rcv1.Details{
			Token: v,
		}
		r, err := pc.RecordDetails(d)
		if err != nil {
			return nil, fmt.Errorf("RecordDetails %v: %v", v, err)
		}

		// Don't include the record if it has been abandoned.
		if r.Status == rcv1.RecordStatusArchived {
			continue
		}

		// Setup vote params
		vp := tkv1.VoteParams{
			Token:            r.CensorshipRecord.Token,
			Version:          r.Version,
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
	ts := tkv1.Start{
		Starts: starts,
	}
	return pc.TicketVoteStart(ts)
}

// voteStartHelpMsg is printed to stdout by the help command.
var voteStartHelpMsg = `votestart <token>

Start a DCR ticket vote for a record. Requires admin privileges.

If the vote is a runoff vote then the --runoff flag must be used. The provided
token should be the parent token of the runoff vote.

Arguments:
1. token (string, required) Record censorship token.

Flags:
 --duration (uint32) Duration, in blocks, of the vote.
                     (default: 6)
 --quorum   (uint32) Percent of total votes required to reach a quorum. A
                     quorum of 0 means that the vote can be approved or
                     rejected using a single DCR ticket.
                     (default: 0)
 --passing  (uint32) Percent of cast votes required for a vote option to be
                     considered as passing.
                     (default: 60)
 --runoff  (bool)    The vote being started is a runoff vote.
                     (default: false)
`
