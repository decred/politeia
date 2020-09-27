// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	pi "github.com/decred/politeia/politeiawww/api/pi/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// voteSummariesCmd retrieves a set of proposal vote summaries.
type voteSummariesCmd struct{}

// Execute executes the batch vote summaries command.
func (cmd *voteSummariesCmd) Execute(args []string) error {
	bpr, err := client.VoteSummaries(&pi.VoteSummaries{
		Tokens: args,
	})
	if err != nil {
		return err
	}

	return shared.PrintJSON(bpr)
}

// voteSummariesHelpMsg is the output for the help command when
// 'votesummaries' is specified.
const voteSummariesHelpMsg = `votesummaries

Fetch a summary of the voting process for a list of proposals.

Example:
votesummaries token1 token2
`
