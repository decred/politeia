// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import "github.com/thi4go/politeia/politeiawww/cmd/shared"

// ActiveVotesCmd retreives all proposals that are currently being voted on.
type ActiveVotesCmd struct{}

// Execute executes the active votes command.
func (cmd *ActiveVotesCmd) Execute(args []string) error {
	// Send request
	avr, err := client.ActiveVotes()
	if err != nil {
		return err
	}

	// Remove the ticket snapshots from the response so that the
	// output is legible
	if !cfg.RawJSON {
		for k := range avr.Votes {
			avr.Votes[k].StartVoteReply.EligibleTickets = []string{
				"removed by politeiawwwcli for readability",
			}
		}
	}

	// Print response details
	return shared.PrintJSON(avr)
}

// activeVotesHelpMsg is the output for the help command when 'activevotes'
// is specified.
const activeVotesHelpMsg = `activevotes "token"

Retrieve all proposals that are currently being voted on.

Arguments: None

Result:
{
  "votes": [
    "proposal": {
      "name":          (string)       Suggested short proposal name 
      "state":         (PropStateT)   Current state of proposal
      "status":        (PropStatusT)  Current status of proposal
      "timestamp":     (int64)        Timestamp of last update of proposal
      "userid":        (string)       ID of user who submitted proposal
      "username":      (string)       Username of user who submitted proposal
      "publickey":     (string)       Public key used to sign proposal
      "signature":     (string)       Signature of merkle root
      "files": [
        {
          "name":      (string)  Filename 
          "mime":      (string)  Mime type 
          "digest":    (string)  File digest 
          "payload":   (string)  File payload 
        }
      ],
      "numcomments":   (uint)  Number of comments on the proposal
      "version": 		 (string)  Version of proposal
      "censorshiprecord": {	
        "token":       (string)  Censorship token
        "merkle":      (string)  Merkle root of proposal
        "signature":   (string)  Server side signature of []byte(Merkle+Token)
      }
    },
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
    "startvotereply": {
      "startblockheight":    (string)  Block height at start of vote
      "startblockhash":      (string)  Hash of first block of vote interval
      "endheight":           (string)  Block height at end of vote
      "eligibletickets": [
        "removed by politeiawwwcli for readability"
      ]
    }
  ]
}
`
