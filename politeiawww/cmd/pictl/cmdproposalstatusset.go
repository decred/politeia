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
		Version uint32 `positional-arg-name:"version"`
	} `positional-args:"true"`
}

// Execute executes the cmdProposalSetStatus command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdProposalSetStatus) Execute(args []string) error {
	_, err := proposalSetStatus(c)
	if err != nil {
		return err
	}
	return nil
}

// proposalSetStatus sets the status of a proposal. This function has been
// pulled out of the Execute method so that is can be used in the test
// commands.
func proposalSetStatus(c *cmdProposalSetStatus) (*rcv1.Record, error) {
	// Verify user identity. This will be needed to sign the status
	// change.
	if cfg.Identity == nil {
		return nil, shared.ErrUserIdentityNotFound
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
		return nil, err
	}

	// Parse status. This can be either the numeric status code or the
	// human readable equivalent.
	status, err := parseRecordStatus(c.Args.Status)
	if err != nil {
		return nil, err
	}

	// Setup version
	var version uint32
	if c.Args.Version != 0 {
		version = c.Args.Version
	} else {
		// Get the version manually
		d := rcv1.Details{
			Token: c.Args.Token,
		}
		r, err := pc.RecordDetails(d)
		if err != nil {
			return nil, err
		}
		version = r.Version
	}

	// Setup request
	msg := c.Args.Token + strconv.FormatUint(uint64(version), 10) +
		strconv.Itoa(int(status)) + c.Args.Reason
	sig := cfg.Identity.SignMessage([]byte(msg))
	ss := rcv1.SetStatus{
		Token:     c.Args.Token,
		Version:   version,
		Status:    status,
		Reason:    c.Args.Reason,
		PublicKey: cfg.Identity.Public.String(),
		Signature: hex.EncodeToString(sig[:]),
	}

	// Send request
	ssr, err := pc.RecordSetStatus(ss)
	if err != nil {
		return nil, err
	}

	// Verify record
	vr, err := client.Version()
	if err != nil {
		return nil, err
	}
	err = pclient.RecordVerify(ssr.Record, vr.PubKey)
	if err != nil {
		return nil, fmt.Errorf("unable to verify record: %v", err)
	}

	// Print proposal to stdout
	err = printProposal(ssr.Record)
	if err != nil {
		return nil, err
	}

	return &ssr.Record, nil
}

func parseRecordState(state string) (rcv1.RecordStateT, error) {
	// Parse status. This can be either the numeric status code or the
	// human readable equivalent.
	var (
		rc rcv1.RecordStateT

		states = map[string]rcv1.RecordStateT{
			"unvetted": rcv1.RecordStateUnvetted,
			"vetted":   rcv1.RecordStateVetted,
			"1":        rcv1.RecordStateUnvetted,
			"2":        rcv1.RecordStateVetted,
		}
	)
	u, err := strconv.ParseUint(state, 10, 32)
	if err == nil {
		// Numeric state code found
		rc = rcv1.RecordStateT(u)
	} else if s, ok := states[state]; ok {
		// Human readable state code found
		rc = s
	} else {
		return rc, fmt.Errorf("invalid state '%v'", state)
	}

	return rc, nil
}

func parseRecordStatus(status string) (rcv1.RecordStatusT, error) {
	// Parse status. This can be either the numeric status code or the
	// human readable equivalent.
	var (
		rc rcv1.RecordStatusT

		statuses = map[string]rcv1.RecordStatusT{
			"public":    rcv1.RecordStatusPublic,
			"censor":    rcv1.RecordStatusCensored,
			"censored":  rcv1.RecordStatusCensored,
			"abandon":   rcv1.RecordStatusArchived,
			"abandoned": rcv1.RecordStatusArchived,
			"archive":   rcv1.RecordStatusArchived,
			"archived":  rcv1.RecordStatusArchived,
			"2":         rcv1.RecordStatusPublic,
			"3":         rcv1.RecordStatusCensored,
			"4":         rcv1.RecordStatusArchived,
		}
	)
	u, err := strconv.ParseUint(status, 10, 32)
	if err == nil {
		// Numeric status code found
		rc = rcv1.RecordStatusT(u)
	} else if s, ok := statuses[status]; ok {
		// Human readable status code found
		rc = s
	} else {
		return rc, fmt.Errorf("invalid status '%v'", status)
	}

	return rc, nil
}

// proposalSetStatusHelpMsg is printed to stdout by the help command.
const proposalSetStatusHelpMsg = `proposalstatusset "token" "status" "reason"

Set the status of a proposal. This command assumes the proposal is a vetted
record. If the proposal is unvetted, the --unvetted flag must be used. Requires
admin priviledges.

Valid statuses:
  public
  censor
  abandon

The following statuses require a status change reason to be included:
  censor
  abandon

Arguments:
1. token   (string, required)  Proposal censorship token
2. status  (string, required)  New status
3. message (string, optional)  Status change message
4. version (string, optional)  Proposal version. This will be retrieved from
                               the backend if one is not provided.
`
