// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"math/rand"
	"strconv"
	"sync"
	"time"

	tkv1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
)

// cmdVoteTest casts all eligible tickets in the user's wallet on all ongoing
// votes.
type cmdVoteTest struct {
	Password string `long:"password" optional:"true"`
}

// Execute executes the cmdVoteTest command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdVoteTest) Execute(args []string) error {
	// Prompt the user for their password if they haven't already
	// provided it.
	password := c.Password
	if password == "" {
		pass, err := promptWalletPassword()
		if err != nil {
			return err
		}
		password = string(pass)
	}

	// We don't want the output of individual commands printed.
	cfg.Verbose = false
	cfg.RawJSON = false
	cfg.Silent = true

	// Get all ongoing votes
	votes := make([]string, 0, 256)
	var page uint32 = 1
	for {
		tokens, err := voteInvForStatus(tkv1.VoteStatusStarted, page)
		if err != nil {
			return err
		}
		if len(tokens) == 0 {
			// We've reached the end of the inventory
			break
		}
		votes = append(votes, tokens...)
		page++
	}
	if len(votes) == 0 {
		return fmt.Errorf("no ongoing votes")
	}

	// Setup vote options
	voteOptions := []string{
		tkv1.VoteOptionIDApprove,
		tkv1.VoteOptionIDReject,
	}

	// Cast ballots concurrently
	var wg sync.WaitGroup
	for _, v := range votes {
		// Select vote option randomly
		r := rand.Intn(len(voteOptions))
		voteOption := voteOptions[r]

		wg.Add(1)
		go func(wg *sync.WaitGroup, token, voteOption, password string) {
			defer wg.Done()

			// Turn printing back on for this part
			cfg.Silent = false

			// Cast ballot
			fmt.Printf("Casting ballot for %v %v\n", token, voteOption)
			start := time.Now()
			err := castBallot(token, voteOption, password)
			if err != nil {
				fmt.Printf("castBallot %v: %v\n", token, err)
			}
			end := time.Now()
			elapsed := end.Sub(start)

			fmt.Printf("%v elapsed time %v\n", token, elapsed)

		}(&wg, v, voteOption, password)
	}

	wg.Wait()

	return nil
}

// voteInvForStatus returns a page of tokens for a vote status.
func voteInvForStatus(s tkv1.VoteStatusT, page uint32) ([]string, error) {
	// Setup command
	c := cmdVoteInv{}
	c.Args.Status = strconv.Itoa(int(s))
	c.Args.Page = page

	// Get inventory
	inv, err := voteInv(&c)
	if err != nil {
		return nil, fmt.Errorf("cmdVoteInv: %v", err)
	}

	// Unpack reply
	sm := tkv1.VoteStatuses[s]
	return inv[sm], nil
}

func castBallot(token, voteID, password string) error {
	c := cmdCastBallot{
		Password: password,
	}
	c.Args.Token = token
	c.Args.VoteID = voteID
	return c.Execute(nil)
}

// voteTestHelpMsg is the printed to stdout by the help command.
const voteTestHelpMsg = `votetest [flags]

Cast dcr ticket votes on all ongoing proposal votes. This command will randomly
select a vote option and cast all eligible tickets for that option.

dcrwallet must be running on localhost and listening on the default dcrwallet
port.

Flags:
 --password (string, required) dcrwallet password. The user will be prompted
                               for their password if one is not provided using
                               this flag.
`
