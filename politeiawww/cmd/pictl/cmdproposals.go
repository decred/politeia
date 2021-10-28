// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	piv1 "github.com/decred/politeia/politeiawww/api/pi/v1"
	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
)

// cmdProposals retrieves the proposal records for the provided tokens.
type cmdProposals struct {
	Args struct {
		Tokens []string `positional-arg-name:"proposals" required:"true"`
	} `positional-args:"true"`
}

// Execute executes the cmdProposals command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdProposals) Execute(args []string) error {
	records, err := proposals(c)
	if err != nil {
		return err
	}

	// Print proposals to stdout
	for _, v := range records {
		err = printProposal(v)
		if err != nil {
			return err
		}
		printf("-----\n")
	}

	return nil
}

// proposals fetches the records API Records route for a page of
// tokens. This function has been pulled out of the Execute method so that
// it can be used in the test commands.
func proposals(c *cmdProposals) (map[string]rcv1.Record, error) {
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

	// Get records
	reqs := make([]rcv1.RecordRequest, 0, len(c.Args.Tokens))
	for _, v := range c.Args.Tokens {
		reqs = append(reqs, rcv1.RecordRequest{
			Token: v,
			Filenames: []string{
				piv1.FileNameProposalMetadata,
				piv1.FileNameVoteMetadata,
			},
		})
	}
	r := rcv1.Records{
		Requests: reqs,
	}
	records, err := pc.Records(r)
	if err != nil {
		return nil, err
	}

	return records, nil
}

// proposalsHelpMsg is printed to stdout by the help command.
const proposalsHelpMsg = `proposals [flags] "tokens..."

Retrieve the proposals for the provided tokens. The proposal index file and the
proposal attachments are not returned from this command. Use the proposal
details command if you are trying to retieve the full proposal.

This command defaults to retrieving vetted proposals unless the --unvetted flag
is used. This command accepts both the full tokens or the token prefixes.

Arguments:
1. tokens  ([]string, required)  Proposal tokens.

Example:
$ pictl proposals f6458c2d8d9ef41c 9f9af91cf609d839 917c6fde9bcc2118
$ pictl proposals f6458c2 9f9af91 917c6fd`
