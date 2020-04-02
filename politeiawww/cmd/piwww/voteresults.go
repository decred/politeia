// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import "github.com/thi4go/politeia/politeiawww/cmd/shared"

// VoteResultsCmd gets the votes that have been cast for the specified
// proposal.
type VoteResultsCmd struct {
	Args struct {
		Token string `positional-arg-name:"token"` // Censorship token
	} `positional-args:"true" required:"true"`
}

// Execute executes the proposal votes command.
func (cmd *VoteResultsCmd) Execute(args []string) error {
	vrr, err := client.VoteResults(cmd.Args.Token)
	if err != nil {
		return err
	}

	// Remove eligible tickets snapshot from response
	// so that the output is legible
	if !cfg.RawJSON {
		vrr.StartVoteReply.EligibleTickets = []string{
			"removed by politeiawwwcli for readability",
		}
	}

	return shared.PrintJSON(vrr)
}

// voteResultsHelpMsg is the output of the help command when 'voteresults' is
// specified.
const voteResultsHelpMsg = `voteresults "token"

Fetch vote results for a proposal.

Arguments:
1. token       (string, required)  Proposal censorship token

Request:
{
  "token":     (string)  Proposal censorship token
}

Response:
{
  "startvote": {
    "publickey"            (string)  Public key of user that submitted proposal
    "vote": {
      "token":             (string)  Censorship token
      "mask"               (uint64)  Valid votebits
      "duration":          (uint32)  Duration of vote in blocks
      "quorumpercentage"   (uint32)  Percent of votes required for quorum
      "passpercentage":    (uint32)  Percent of votes required to pass
      "options": [
        {
          "id"             (string)  Unique word identifying vote (e.g. yes)
          "description"    (string)  Longer description of the vote
          "bits":          (uint64)  Bits used for this option
        },
      ]
    },
    "signature"            (string)  Signature of Votehash
  },
  "castvotes": [],
  "startvotereply": {
    "startblockheight":    (string)  Block height at start of vote
    "startblockhash":      (string)  Hash of first block of vote interval
    "endheight":           (string)  Block height at end of vote
    "eligibletickets": [
      "removed by politeiawwwcli for readability"
    ]
  }
}`
