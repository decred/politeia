// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"fmt"
	"strconv"

	piv1 "github.com/decred/politeia/politeiawww/api/pi/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// cmdProposalSetBillingStatus sets the status of a proposal.
type cmdProposalSetBillingStatus struct {
	Args struct {
		Token  string `positional-arg-name:"token" required:"true"`
		Status string `positional-arg-name:"status" required:"true"`
		Reason string `positional-arg-name:"reason"`
	} `positional-args:"true"`
}

// Execute executes the cmdProposalSetBillingStatus command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdProposalSetBillingStatus) Execute(args []string) error {
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

	// Parse billing status. This can be either the numeric status code or the
	// human readable equivalent.
	status, err := parseBillingStatus(c.Args.Status)
	if err != nil {
		return err
	}

	// Setup request
	msg := c.Args.Token + strconv.Itoa(int(status)) + c.Args.Reason
	sig := cfg.Identity.SignMessage([]byte(msg))
	sbs := piv1.SetBillingStatus{
		Token:     c.Args.Token,
		Status:    status,
		Reason:    c.Args.Reason,
		PublicKey: cfg.Identity.Public.String(),
		Signature: hex.EncodeToString(sig[:]),
	}

	// Send request
	sbsr, err := pc.PiSetBillingStatus(sbs)
	if err != nil {
		return err
	}

	// Print receipt
	printf("Token    : %v\n", sbs.Token)
	printf("Status   : %v\n", piv1.BillingStatuses[sbs.Status])
	printf("Timestamp: %v\n", dateAndTimeFromUnix(sbsr.Timestamp))
	printf("Receipt  : %v\n", sbsr.Receipt)
	return nil
}

func parseBillingStatus(status string) (piv1.BillingStatusT, error) {
	// Parse billing status. This can be either the numeric status code or the
	// human readable equivalent.
	var (
		bs piv1.BillingStatusT

		statuses = map[string]piv1.BillingStatusT{
			"active":    piv1.BillingStatusActive,
			"close":     piv1.BillingStatusClosed,
			"closed":    piv1.BillingStatusClosed,
			"complete":  piv1.BillingStatusCompleted,
			"completed": piv1.BillingStatusCompleted,
		}
	)
	u, err := strconv.ParseUint(status, 10, 32)
	if err == nil {
		// Numeric status code found
		bs = piv1.BillingStatusT(u)
	} else if s, ok := statuses[status]; ok {
		// Human readable status code found
		bs = s
	} else {
		return bs, fmt.Errorf("invalid status '%v'", status)
	}

	return bs, nil
}

// proposalSetBillingStatusHelpMsg is printed to stdout by the help command.
const proposalSetBillingStatusHelpMsg = `proposalsetbillingstatus "token" "status" "reason"

Set the billing status of a proposal.

Valid statuses:
  (1) active
  (2) close
  (3) complete

The following statuses require a billing status change reason to be included:
  close

Arguments:
1. token   (string, required)   Proposal censorship token
2. status  (string, required)   New billing status
3. reason  (string, optional)   Billing status change reason
`
