// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	www "github.com/decred/politeia/politeiawww/api/www/v1"
)

type cmdLegacyTest struct {
}

// Execute executes the cmdLegacyTest command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdLegacyTest) Execute(args []string) error {
	printf("Policy\n")
	pr, err := client.Policy()
	if err != nil {
		return err
	}
	printJSON(pr)

	printf("Token inventory\n")
	tir, err := client.TokenInventory()
	if err != nil {
		return err
	}
	printJSON(tir)

	printf("All vetted\n")
	avr, err := client.GetAllVetted(&www.GetAllVetted{})
	if err != nil {
		return err
	}
	printJSON(avr)

	if len(tir.Pre) == 0 {
		return fmt.Errorf("no proposals found; cannot get proposal details")
	}
	token := tir.Pre[0]

	printf("Proposal details %v\n", token)
	pdr, err := client.ProposalDetails(token, &www.ProposalsDetails{})
	if err != nil {
		return err
	}
	printJSON(pdr)

	printf("Batch proposals %v\n", token)
	bp := www.BatchProposals{
		Tokens: []string{token},
	}
	bpr, err := client.BatchProposals(&bp)
	if err != nil {
		return err
	}
	printJSON(bpr)

	printf("All vote status\n")
	avsr, err := client.GetAllVoteStatus()
	if err != nil {
		return err
	}
	printJSON(avsr)

	if len(tir.Approved) == 0 {
		return fmt.Errorf("no vote approvals found; cannot get vote status")
	}
	token = tir.Approved[0]

	printf("Vote status %v\n", token)
	vsr, err := client.VoteStatus(token)
	if err != nil {
		return err
	}
	printJSON(vsr)

	printf("Vote results %v\n", token)
	vrr, err := client.VoteResults(token)
	if err != nil {
		return err
	}
	vrr.StartVoteReply.EligibleTickets = []string{
		fmt.Sprintf("%v ticket hashes removed for readability",
			len(vrr.StartVoteReply.EligibleTickets)),
	}
	printJSON(vrr)

	return nil
}
