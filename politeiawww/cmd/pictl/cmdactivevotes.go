// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

// cmdActiveVotes retreives all proposals that are currently being voted on.
type cmdActiveVotes struct{}

// Execute executes the active votes command.
func (cmd *cmdActiveVotes) Execute(args []string) error {
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
	printJSON(avr)

	return nil
}
