// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import "github.com/thi4go/politeia/politeiawww/cmd/shared"

// VoteStatusesCmd retreives the vote status of all public proposals.
type VoteStatusesCmd struct{}

// Execute executes the vote statuses command.
func (cmd *VoteStatusesCmd) Execute(args []string) error {
	avsr, err := client.GetAllVoteStatus()
	if err != nil {
		return err
	}
	return shared.PrintJSON(avsr)
}

// voteStatusesHelpMsg is the output for the help command when 'votestatuses'
// is specified.
const voteStatusesHelpMsg = `votestatuses

Fetch vote status of all public proposals.

Proposal vote status codes:

'0' - Invalid vote status
'1' - Vote has not been authorized by proposal author
'2' - Vote has been authorized by proposal author
'3' - Proposal vote has been started
'4' - Proposal vote has been finished
'5' - Proposal doesn't exist

Arguments: None

Response:
{
  "votestatus": [
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
    }
  ]
}`
