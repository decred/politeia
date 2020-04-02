// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import "github.com/thi4go/politeia/politeiawww/cmd/shared"

// VoteStatusCmd gets the vote status of the specified proposal.
type VoteStatusCmd struct {
	Args struct {
		Token string `positional-arg-name:"token"` // Censorship token
	} `positional-args:"true" required:"true"`
}

// Execute executes the vote status command.
func (cmd *VoteStatusCmd) Execute(args []string) error {
	vsr, err := client.VoteStatus(cmd.Args.Token)
	if err != nil {
		return err
	}
	return shared.PrintJSON(vsr)
}

// voteStatusHelpMsg is the output of the help command when 'votestatus' is
// specified.
const voteStatusHelpMsg = `votestatus "token"

Fetch vote status for a proposal.

Proposal vote status codes:

'0' - Invalid vote status
'1' - Vote has not been authorized by proposal author
'2' - Vote has been authorized by proposal author
'3' - Proposal vote has been started
'4' - Proposal vote has been finished
'5' - Proposal doesn't exist

Arguments:
1. token       (string, required)  Proposal censorship token

Request:
{
  "token":     (string)  Proposal censorship token
}

Response:
{
  "token":              (string)  Public key of user that submitted proposal
  "status":             (int)     Vote status code
  "totalvotes":         (uint64)  Total number of votes on proposal
  "optionsresult": [
    {
      "option": {
        "id":           (string)  Unique word identifying vote (e.g. 'yes')
        "description":  (string)  Longer description of the vote
        "bits":         (uint64)  Bits used for this option
      },
      "votesreceived":  (uint64)  Number of votes received
    },
  ],
  "endheight":          (string)  String encoded final block height of the vote
  "numofeligiblevotes": (int)     Total number of eligible votes
  "quorumpercentage":   (uint32)  Percent of eligible votes required for quorum
  "passpercentage":     (uint32)  Percent of total votes required to pass
}`
