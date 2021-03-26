// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
)

// cmdProposalTimestamps retrieves the timestamps for a politeiawww proposal.
type cmdProposalTimestamps struct {
	Args struct {
		Token   string `positional-arg-name:"token" required:"true"`
		Version uint32 `positional-arg-name:"version" optional:"true"`
	} `positional-args:"true"`
}

// Execute executes the cmdProposalTimestamps command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdProposalTimestamps) Execute(args []string) error {
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

	// Get timestamps
	t := rcv1.Timestamps{
		Token:   c.Args.Token,
		Version: c.Args.Version,
	}
	tr, err := pc.RecordTimestamps(t)
	if err != nil {
		return err
	}

	// Verify timestamps
	err = pclient.RecordTimestampsVerify(*tr)
	if err != nil {
		return err
	}

	// Print timestamps
	printJSON(tr)

	return nil
}

// proposalTimestampsHelpMsg is printed to stdout by the help command.
const proposalTimestampsHelpMsg = `proposaltimestamps [flags] "token" "version"

Fetch the timestamps a proposal version. The timestamp contains all necessary
data to verify that user submitted proposal data has been timestamped onto the
decred blockchain.

This command defaults to requesting vetted proposals unless the --unvetted flag
is used.

Arguments:
1. token    (string, required) Record token
2. version  (uint32, optional) Record version
`
