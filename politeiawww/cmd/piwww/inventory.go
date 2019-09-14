// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"strconv"

	"github.com/decred/dcrwallet/rpc/walletrpc"
)

// InventoryCmd retreives the proposals that are being voted on.
type InventoryCmd struct{}

// Execute executes the inventory command.
func (cmd *InventoryCmd) Execute(args []string) error {
	// Connect to user's wallet
	err := client.LoadWalletClient()
	if err != nil {
		return fmt.Errorf("LoadWalletClient: %v", err)
	}
	defer client.Close()

	// Get all active proposal votes
	avr, err := client.ActiveVotes()
	if err != nil {
		return fmt.Errorf("ActiveVotes: %v", err)
	}

	// Get current block height
	ar, err := client.WalletAccounts()
	if err != nil {
		return fmt.Errorf("WalletAccounts: %v", err)
	}

	// Validate active votes and print the details of the
	// votes that the user is eligible to vote in
	for _, v := range avr.Votes {
		// Ensure a CensorshipRecord exists
		if v.Proposal.CensorshipRecord.Token == "" {
			// This should not happen
			fmt.Printf("skipping empty CensorshipRecord\n")
			continue
		}

		// Ensure vote bits are valid
		if v.StartVote.Vote.Token == "" || v.StartVote.Vote.Mask == 0 ||
			v.StartVote.Vote.Options == nil {
			// This should not happen
			fmt.Printf("invalid vote bits: %v", v.Proposal.CensorshipRecord.Token)
			continue
		}

		// Ensure vote has not expired
		endHeight, err := strconv.ParseInt(v.StartVoteReply.EndHeight, 10, 32)
		if err != nil {
			return err
		}

		if int64(ar.CurrentBlockHeight) > endHeight {
			// This should not happen
			fmt.Printf("Vote expired: current %v > end %v %v\n",
				endHeight, ar.CurrentBlockHeight, v.StartVote.Vote.Token)
			continue
		}

		// Ensure user has eligible tickets for this proposal vote
		ticketPool, err := convertTicketHashes(v.StartVoteReply.EligibleTickets)
		if err != nil {
			return err
		}

		ctr, err := client.CommittedTickets(
			&walletrpc.CommittedTicketsRequest{
				Tickets: ticketPool,
			})
		if err != nil {
			return fmt.Errorf("CommittedTickets: %v", err)
		}

		if len(ctr.TicketAddresses) == 0 {
			// User doesn't have any eligible tickets
			fmt.Printf("Token: %v\n", v.StartVote.Vote.Token)
			fmt.Printf("  Proposal        : %v\n", v.Proposal.Name)
			fmt.Printf("  Eligible tickets: %v\n", len(ctr.TicketAddresses))
			continue
		}

		// Print details for the active proposal votes where
		// the user has eligible tickets
		fmt.Printf("Token: %v\n", v.StartVote.Vote.Token)
		fmt.Printf("  Proposal        : %v\n", v.Proposal.Name)
		fmt.Printf("  Eligible tickets: %v\n", len(ctr.TicketAddresses))
		fmt.Printf("  Start block     : %v\n", v.StartVoteReply.StartBlockHeight)
		fmt.Printf("  End block       : %v\n", v.StartVoteReply.EndHeight)
		fmt.Printf("  Mask            : %v\n", v.StartVote.Vote.Mask)
		for _, vo := range v.StartVote.Vote.Options {
			fmt.Printf("  Vote Option:\n")
			fmt.Printf("    ID                   : %v\n", vo.Id)
			fmt.Printf("    Description          : %v\n",
				vo.Description)
			fmt.Printf("    Bits                 : %v\n", vo.Bits)
			fmt.Printf("    To choose this option: politeiawwwcli vote %v %v\n",
				v.StartVote.Vote.Token, vo.Id)
		}
	}

	return nil
}

// inventoryHelpMsg is the output of the help command when 'inventory' is
// specified.
const inventoryHelpMsg = `inventory

Fetch the proposals that are being voted on.

Arguments:
None

Response:

Token: (string)  Proposal censorship token
  Proposal        : (string)  Proposal name
  Eligible tickets: (int)  Number of eligible tickets
  Start block     : (string)  Block height at start of vote
  End block       : (string)  Block height at end of vote
  Mask            : (uint64)  Valid votebits
  Vote Option:
    ID                   : (string)  Unique word identifying vote (e.g. 'no')
    Description          : (string)  Longer description of the vote
    Bits                 : (uint64)  Bits used for this option (e.g. '1')
  Vote Option:
    ID                   : (string)  Unique word identifying vote (e.g. 'yes')
    Description          : (string)  Longer description of the vote
    Bits                 : (uint64)  Bits used for this option (e.g. '2')
    To choose this option: politeiawwwcli vote 'Token' 'ID'`
