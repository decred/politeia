// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// ProposalTimelineCmd retrieves a timeline of events related to the
// history of a proposal.
type ProposalTimelineCmd struct {
	Args struct {
		Token string `positional-arg-name:"token" required:"true"` // Censorship token
	} `positional-args:"true"`
}

// Execute executes the proposal timeline command
func (cmd *ProposalTimelineCmd) Execute(args []string) error {
	// Get timestamps
	vtsr, err := client.ProposalTimeline(cmd.Args.Token)
	if err != nil {
		return err
	}

	// Print proposal timeline reply
	return shared.PrintJSON(vtsr)
}

// proposalTimelineHelpMsg is the output for the help command when
// 'proposaltimeline' is specified.
const proposalTimelineHelpMsg = `proposaltimeline "token"
Get a timeline of events related to the lifycycle of a proposal.
Arguments:
1. token      (string, required)   Censorship token
Result:
{
	"versionTimestamps": [
	  {
		"created": (uint64) timestamp when version was created
		"vetted":  (uint64) timestamp when version was vetted by an admin
		"authorized": {
		  "action"      (string) whether or not the authorization was revoked
		  "timestamp"   (uint64) time when authorization action was taken
		}
	  }
	]
	"startVoteBlock" (uint64) block when voting period ends
	"endVoteBlock"   (uint64) block when voting period starts
  }
}`
