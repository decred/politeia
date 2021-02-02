// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	piv1 "github.com/decred/politeia/politeiawww/api/pi/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
)

// cmdProposals retrieves the proposal records for the provided tokens.
type cmdProposals struct {
	Args struct {
		Tokens []string `positional-arg-name:"proposals" required:"true"`
	} `positional-args:"true" optional:"true"`

	// Unvetted is used to indicate the state of the proposals are
	// unvetted. If this flag is not used it will be assumed that the
	// proposals are vetted.
	Unvetted bool `long:"unvetted" optional:"true"`
}

// Execute executes the cmdProposals command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdProposals) Execute(args []string) error {
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
		state = piv1.ProposalStateUnvetted
	default:
		state = piv1.ProposalStateVetted
	}

	// Get proposal details
	p := piv1.Proposals{
		State:  state,
		Tokens: c.Args.Tokens,
	}
	pr, err := pc.PiProposals(p)
	if err != nil {
		return err
	}

	// Print proposals to stdout
	for _, v := range pr.Proposals {
		r, err := convertProposal(v)
		if err != nil {
			return err
		}
		err = printProposal(*r)
		if err != nil {
			return err
		}
	}

	return nil
}

// proposalsHelpMsg is printed to stdout by the help command.
const proposalsHelpMsg = `proposals [flags] "tokens..."

Retrive the proposals for the provided tokens. The proposal index file and the
proposal attachments are not returned from this command. Use the proposal
details command if you are trying to retieve the full proposal.

This command defaults to retrieving vetted proposals unless the --unvetted flag
is used.

Arguments:
1. tokens  ([]string, required)  Proposal tokens.

Flags:
 --unvetted  (bool, optional)  Retrieve unvetted proposals.
`
