// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import "github.com/decred/politeia/politeiawww/cmd/shared"

// ActiveVotesCmd retreives all dccs that are currently being voted on.
type ActiveVotesCmd struct{}

// Execute executes the active votes command.
func (cmd *ActiveVotesCmd) Execute(args []string) error {
	// Send request
	avr, err := client.ActiveVotesDCC()
	if err != nil {
		return err
	}

	// Print response details
	return shared.PrintJSON(avr)
}

// activeVotesHelpMsg is the output for the help command when 'activevotes'
// is specified.
const activeVotesHelpMsg = `activevotes "token"

Retrieve all dccs that are currently being voted on.

Arguments: None

Result:
{
  "votes": [
    "dcc": {
      "name":          (string)       Suggested short dcc name 
      "state":         (PropStateT)   Current state of dcc
      "status":        (PropStatusT)  Current status of dcc
      "timestamp":     (int64)        Timestamp of last update of dcc
      "userid":        (string)       ID of user who submitted dcc
      "username":      (string)       Username of user who submitted dcc
      "publickey":     (string)       Public key used to sign dcc
      "signature":     (string)       Signature of merkle root
      "files": [
        {
          "name":      (string)  Filename 
          "mime":      (string)  Mime type 
          "digest":    (string)  File digest 
          "payload":   (string)  File payload 
        }
      ],
      "numcomments":   (uint)  Number of comments on the dcc
      "version": 		 (string)  Version of dcc
      "censorshiprecord": {	
        "token":       (string)  Censorship token
        "merkle":      (string)  Merkle root of dcc
        "signature":   (string)  Server side signature of []byte(Merkle+Token)
      }
    },
    "startvote": {
      "publickey"            (string)  Public key of user that submitted dcc
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
