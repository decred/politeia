// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	v1 "github.com/thi4go/politeia/politeiawww/api/www/v1"
	"github.com/thi4go/politeia/politeiawww/cmd/shared"
)

// BatchVoteSummaryCmd retrieves a set of proposal vote summaries.
type BatchVoteSummaryCmd struct{}

// Execute executes the batch vote summaries command.
func (cmd *BatchVoteSummaryCmd) Execute(args []string) error {
	bpr, err := client.BatchVoteSummary(&v1.BatchVoteSummary{
		Tokens: args,
	})
	if err != nil {
		return err
	}

	return shared.PrintJSON(bpr)
}

// batchVoteSummaryHelpMsg is the output for the help command when
// 'batchvotesummary' is specified.
const batchVoteSummaryHelpMsg = `batchvotesummary 

Fetch a summary of the voting process for a list of proposals.

Example:
batchvotesummary token1 token2

Result:
{
  "statuses": {
    "token": {(                   (string)  Censorship token of proposal
      "status":                   (int)     Vote status code,
      "eligibletickets":          (uint32)  Number of tickets eligible to vote
      "endheight":                (uint64)  Final voting block of proposal
      "bestblock":                (uint64)  Current block
      "quorumpercentage":         (uint32)  Percent of eligible votes required for quorum
      "passpercentage":           (uint32)  Percent of total votes required to pass
      "results": [
        {
          "option": {
            "id":                 (string)  Unique word identifying vote (e.g. 'yes')
            "description":        (string)  Longer description of the vote
            "bits":               (uint64)  Bits used for this option
          },
          "votesreceived":        (uint64)  Number of votes received
        }
      ]
    }
  }
}`
