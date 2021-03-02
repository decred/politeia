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

type cmdVoteTest struct {
	Args struct {
		Password string `positional-arg-name:"password"`
	} `positional-args:"true" required:"true"`
}

// Execute executes the cmdVoteTest command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdVoteTest) Execute(args []string) error {
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

		}(&wg, v, voteOption, c.Args.Password)
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
