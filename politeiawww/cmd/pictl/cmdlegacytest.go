// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	www "github.com/decred/politeia/politeiawww/api/www/v1"
)

// cmdLegacyTest tests the legacy www routes. These routes have been deprecated
// and do not have corresponding pictl commands.
type cmdLegacyTest struct {
	Args struct {
		AdminEmail    string `positional-arg-name:"adminemail" required:"true"`
		AdminPassword string `positional-arg-name:"adminpassword" required:"true"`
	} `positional-args:"true"`
}

// Execute executes the cmdLegacyTest command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdLegacyTest) Execute(args []string) error {
	// Verify admin login credentials
	admin := user{
		Email:    c.Args.AdminEmail,
		Password: c.Args.AdminPassword,
	}
	err := userLogin(admin)
	if err != nil {
		return fmt.Errorf("failed to login admin: %v", err)
	}
	lr, err := client.Me()
	if err != nil {
		return err
	}
	if !lr.IsAdmin {
		return fmt.Errorf("provided user is not an admin")
	}
	admin.Username = lr.Username

	// Verify paywall is disabled
	policyWWW, err := client.Policy()
	if err != nil {
		return err
	}
	if policyWWW.PaywallEnabled {
		return fmt.Errorf("paywall is not disabled")
	}

	// Seed the backend with proposals
	proposalCount := 10
	tokens := make([]string, 0, proposalCount)
	for i := 0; i < proposalCount; i++ {
		s := fmt.Sprintf("Creating proposal %v/%v", i+1, proposalCount)
		printInPlace(s)

		r, err := proposalPublic(admin, admin, false)
		if err != nil {
			return err
		}
		tokens = append(tokens, r.CensorshipRecord.Token)
	}
	fmt.Printf("\n")

	// Start the voting period on all proposals
	for i, v := range tokens {
		s := fmt.Sprintf("Starting voting period %v/%v", i+1, proposalCount)
		printInPlace(s)

		err = voteAuthorize(admin, v)
		if err != nil {
			return err
		}
		err = voteStart(admin, v, 1000, 1, 50)
		if err != nil {
			return err
		}
	}
	fmt.Printf("\n")

	fmt.Printf("Policy\n")
	pr, err := client.Policy()
	if err != nil {
		return err
	}
	printJSON(pr)

	fmt.Printf("Token inventory\n")
	tir, err := client.TokenInventory()
	if err != nil {
		return err
	}
	printJSON(tir)

	fmt.Printf("All vetted\n")
	avr, err := client.GetAllVetted(&www.GetAllVetted{})
	if err != nil {
		return err
	}
	printJSON(avr)

	token := tokens[0]
	fmt.Printf("Proposal details %v\n", token)
	pdr, err := client.ProposalDetails(token, &www.ProposalsDetails{})
	if err != nil {
		return err
	}
	printJSON(pdr)

	fmt.Printf("Batch proposals\n")
	bp := www.BatchProposals{
		Tokens: tokens,
	}
	bpr, err := client.BatchProposals(&bp)
	if err != nil {
		return err
	}
	if len(bpr.Proposals) != proposalCount {
		return fmt.Errorf("got %v proposals, want %v",
			len(bpr.Proposals), proposalCount)
	}
	printJSON(bpr)

	fmt.Printf("All vote status\n")
	avsr, err := client.GetAllVoteStatus()
	if err != nil {
		return err
	}
	printJSON(avsr)

	if len(tir.Approved) == 0 {
		return fmt.Errorf("no vote approvals found; cannot get vote status")
	}
	token = tir.Approved[0]

	fmt.Printf("Vote status %v\n", token)
	vsr, err := client.VoteStatus(token)
	if err != nil {
		return err
	}
	printJSON(vsr)

	fmt.Printf("Vote results %v\n", token)
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
