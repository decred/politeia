package commands

import (
	"fmt"
	"strconv"

	"github.com/decred/dcrwallet/rpc/walletrpc"
)

type InventoryCmd struct{}

func (cmd *InventoryCmd) Execute(args []string) error {
	// Connect to user's wallet
	err := c.LoadWalletClient()
	if err != nil {
		return fmt.Errorf("LoadWalletClient: %v", err)
	}

	// Get all active proposal votes
	avr, err := c.ActiveVotes()
	if err != nil {
		return fmt.Errorf("ActiveVotes: %v", err)
	}

	// Get current block height
	ar, err := c.WalletAccounts()
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
		ticketPool, err := ConvertTicketHashes(v.StartVoteReply.EligibleTickets)
		if err != nil {
			return err
		}

		ctr, err := c.CommittedTickets(&walletrpc.CommittedTicketsRequest{
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
