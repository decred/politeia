// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"fmt"
	"strconv"

	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// cmdProposalSetStatus sets the status of a proposal.
type cmdProposalSetStatus struct {
	Args struct {
		Token   string `positional-arg-name:"token" required:"true"`
		Status  string `positional-arg-name:"status" required:"true"`
		Reason  string `positional-arg-name:"reason"`
		Version string `positional-arg-name:"version"`
	} `positional-args:"true"`

	// Unvetted is used to indicate the state of the proposal is
	// unvetted. If this flag is not used it will be assumed that
	// the proposal is vetted.
	Unvetted bool `long:"unvetted" optional:"true"`
}

// Execute executes the cmdProposalSetStatus command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdProposalSetStatus) Execute(args []string) error {
	// Verify user identity. This will be needed to sign the status
	// change.
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

	// Setup state
	var state string
	switch {
	case c.Unvetted:
		state = rcv1.RecordStateUnvetted
	default:
		state = rcv1.RecordStateVetted
	}

	// Parse status. This can be either the numeric status code or the
	// human readable equivalent.
	var (
		status rcv1.RecordStatusT

		statuses = map[string]rcv1.RecordStatusT{
			"public":    rcv1.RecordStatusPublic,
			"censored":  rcv1.RecordStatusCensored,
			"abandoned": rcv1.RecordStatusArchived,
			"2":         rcv1.RecordStatusPublic,
			"3":         rcv1.RecordStatusCensored,
			"4":         rcv1.RecordStatusArchived,
		}
	)
	s, err := strconv.ParseUint(c.Args.Status, 10, 32)
	if err == nil {
		// Numeric status code found
		status = rcv1.RecordStatusT(s)
	} else if s, ok := statuses[c.Args.Status]; ok {
		// Human readable status code found
		status = s
	} else {
		return fmt.Errorf("invalid proposal status '%v'\n %v",
			c.Args.Status, proposalSetStatusHelpMsg)
	}

	// Setup version
	var version string
	if c.Args.Version != "" {
		version = c.Args.Version
	} else {
		// Get the version manually
		d := rcv1.Details{
			State: state,
			Token: c.Args.Token,
		}
		r, err := pc.RecordDetails(d)
		if err != nil {
			return err
		}
		version = r.Version
	}

	// Setup request
	msg := c.Args.Token + version + strconv.Itoa(int(status)) + c.Args.Reason
	sig := cfg.Identity.SignMessage([]byte(msg))
	ss := rcv1.SetStatus{
		Token:     c.Args.Token,
		State:     state,
		Version:   version,
		Status:    status,
		Reason:    c.Args.Reason,
		PublicKey: cfg.Identity.Public.String(),
		Signature: hex.EncodeToString(sig[:]),
	}

	// Send request
	ssr, err := pc.RecordSetStatus(ss)
	if err != nil {
		return err
	}

	// Verify record
	vr, err := client.Version()
	if err != nil {
		return err
	}
	err = pclient.RecordVerify(ssr.Record, vr.PubKey)
	if err != nil {
		return fmt.Errorf("unable to verify record: %v", err)
	}

	// Print proposal to stdout
	err = printProposal(ssr.Record)
	if err != nil {
		return err
	}

	return nil
}

// proposalSetStatusHelpMsg is printed to stdout by the help command.
const proposalSetStatusHelpMsg = `proposalstatusset "token" "status" "reason"

Set the status of a proposal. This command assumes the proposal is a vetted
record. If the proposal is unvetted, the --unvetted flag must be used. Requires
admin priviledges.

Valid statuses:
  public
  censored
  abandoned

The following statuses require a status change reason to be included:
  censored
  abandoned

Arguments:
1. token   (string, required)  Proposal censorship token
2. status  (string, required)  New status
3. message (string, optional)  Status change message
4. version (string, optional)  Proposal version. This will be retrieved from
                               the backend if one is not provided.

Flags:
  --unvetted (bool, optional)  Set status of an unvetted record.
`
