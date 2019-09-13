// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"strconv"
)

// TallyCmd retrieves all of the cast votes for a proposal, tallies the votes,
// and displays the result.
type TallyCmd struct {
	Args struct {
		Token string `positional-arg-name:"token"` // Censorship token
	} `positional-args:"true" required:"true"`
}

// Execute executes the tally command.
func (cmd *TallyCmd) Execute(args []string) error {
	// Get vote results for proposal
	vrr, err := client.VoteResults(cmd.Args.Token)
	if err != nil {
		return fmt.Errorf("ProposalVotes: %v", err)
	}

	// Tally votes
	var total uint
	tally := make(map[uint64]uint)
	for _, v := range vrr.CastVotes {
		bits, err := strconv.ParseUint(v.VoteBit, 10, 64)
		if err != nil {
			return err
		}
		tally[bits]++
		total++
	}

	if total == 0 {
		return fmt.Errorf("no votes recorded")
	}

	// Print results
	for _, vo := range vrr.StartVote.Vote.Options {
		votes := tally[vo.Bits]
		fmt.Printf("Vote Option:\n")
		fmt.Printf("  ID                   : %v\n", vo.Id)
		fmt.Printf("  Description          : %v\n", vo.Description)
		fmt.Printf("  Bits                 : %v\n", vo.Bits)
		fmt.Printf("  Votes received       : %v\n", votes)
		fmt.Printf("  Percentage           : %v%%\n",
			float64(votes)/float64(total)*100)
	}

	return nil
}

// tallyHelpMsg is the output for the help command when 'tally' is specified.
const tallyHelpMsg = `tally "token"

Fetch the vote tally for a proposal.

Arguments:
1. token       (string, required)  Proposal censorship token

Response:

Vote Option:
  ID                   : (string)  Unique word identifying vote (e.g. 'no')
  Description          : (string)  Longer description of the vote
  Bits                 : (uint64)  Bits used for this option (e.g. '1')
  Votes received       : (uint)    Number of votes received
  Percentage           : (float64) Percentage of votes for vote option 
Vote Option:
  ID                   : (string)  Unique word identifying vote (e.g. 'yes')
  Description          : (string)  Longer description of the vote
  Bits                 : (uint64)  Bits used for this option (e.g. '2')
  Votes received       : (uint)    Number of votes received
  Percentage           : (float64) Percentage of votes for vote option`
