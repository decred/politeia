// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"

	"decred.org/dcrwallet/rpc/walletrpc"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	pi "github.com/decred/politeia/politeiawww/api/pi/v1"
	"github.com/decred/politeia/util"
	"golang.org/x/crypto/ssh/terminal"
)

// voteBallotCmd casts a ballot of votes for the specified proposal.
type voteBallotCmd struct {
	Args struct {
		Token  string `positional-arg-name:"token"`  // Censorship token
		VoteID string `positional-arg-name:"voteid"` // Vote choice ID
	} `positional-args:"true" required:"true"`
}

// Execute executes the vote ballot command.
func (cmd *voteBallotCmd) Execute(args []string) error {
	token := cmd.Args.Token
	voteID := cmd.Args.VoteID

	// Connet to user's wallet
	err := client.LoadWalletClient()
	if err != nil {
		return fmt.Errorf("LoadWalletClient: %v", err)
	}
	defer client.Close()

	// Get server public key
	vr, err := client.Version()
	if err != nil {
		return fmt.Errorf("Version: %v", err)
	}

	serverID, err := util.IdentityFromString(vr.PubKey)
	if err != nil {
		return err
	}

	// Get vote details of provided proposal
	avr, err := client.Votes(pi.Votes{
		Tokens: []string{token},
	})
	if err != nil {
		return fmt.Errorf("Votes: %v", err)
	}

	// Find the proposal that the user wants to vote on
	pvt, ok := avr.Votes[token]
	if !ok {
		return fmt.Errorf("proposal not found: %v", token)
	}

	// Ensure that the passed in voteID is one of the
	// proposal's voting options and save the vote bits
	var voteBit string
	for _, option := range pvt.Vote.Params.Options {
		if voteID == option.ID {
			voteBit = strconv.FormatUint(option.Bit, 16)
			break
		}
	}

	if voteBit == "" {
		return fmt.Errorf("vote id not found: %v", voteID)
	}

	// Find user's tickets that are eligible to vote on this
	// proposal
	ticketPool, err := convertTicketHashes(pvt.Vote.EligibleTickets)
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
		return fmt.Errorf("user has no eligible tickets: %v",
			token)
	}

	// Create slice of hexadecimal ticket hashes to represent
	// the user's eligible tickets
	eligibleTickets := make([]string, 0, len(ctr.TicketAddresses))
	for i, v := range ctr.TicketAddresses {
		h, err := chainhash.NewHash(v.Ticket)
		if err != nil {
			return fmt.Errorf("NewHash failed on index %v: %v", i, err)
		}
		eligibleTickets = append(eligibleTickets, h.String())
	}

	// Prompt user for wallet password
	var passphrase []byte
	for len(passphrase) == 0 {
		fmt.Printf("Enter the private passphrase of your wallet: ")
		pass, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return err
		}
		fmt.Printf("\n")
		passphrase = bytes.TrimSpace(pass)
	}

	// Sign eligible tickets with vote preference
	messages := make([]*walletrpc.SignMessagesRequest_Message, 0,
		len(eligibleTickets))
	for i, v := range ctr.TicketAddresses {
		// ctr.TicketAddresses and eligibleTickets use the same index
		msg := token + eligibleTickets[i] + voteBit
		messages = append(messages, &walletrpc.SignMessagesRequest_Message{
			Address: v.Address,
			Message: msg,
		})
	}

	sigs, err := client.SignMessages(&walletrpc.SignMessagesRequest{
		Passphrase: passphrase,
		Messages:   messages,
	})
	if err != nil {
		return fmt.Errorf("SignMessages: %v", err)
	}

	// Validate signatures
	for i, r := range sigs.Replies {
		if r.Error != "" {
			return fmt.Errorf("signature failed index %v: %v", i, r.Error)
		}
	}

	// Setup cast votes request
	votes := make([]pi.CastVote, 0, len(eligibleTickets))
	for i, ticket := range eligibleTickets {
		// eligibleTickets and sigs use the same index
		votes = append(votes, pi.CastVote{
			Token:     token,
			Ticket:    ticket,
			VoteBit:   voteBit,
			Signature: hex.EncodeToString(sigs.Replies[i].Signature),
		})
	}

	// Cast proposal votes
	br, err := client.VoteBallot(&pi.VoteBallot{
		Votes: votes,
	})
	if err != nil {
		return fmt.Errorf("VoteBallot: %v", err)
	}

	// Check for any failed votes. Vote receipts don't include
	// the ticket hash so in order to associate a failed
	// receipt with a specific ticket, we need  to lookup the
	// ticket hash and store it separately.
	failedReceipts := make([]pi.CastVoteReply, 0, len(br.Receipts))
	failedTickets := make([]string, 0, len(eligibleTickets))
	for i, v := range br.Receipts {
		// Lookup ticket hash
		// br.Receipts and eligibleTickets use the same index
		h := eligibleTickets[i]

		// Check for voting error
		if v.ErrorContext != "" {
			failedReceipts = append(failedReceipts, v)
			failedTickets = append(failedTickets, h)
			continue
		}

		// Validate server signature
		sig, err := identity.SignatureFromString(v.Receipt)
		if err != nil {
			v.ErrorContext = err.Error()
			failedReceipts = append(failedReceipts, v)
			failedTickets = append(failedTickets, h)
			continue
		}

		clientSig := votes[i].Signature
		if !serverID.VerifyMessage([]byte(clientSig), *sig) {
			v.ErrorContext = "Could not verify receipt " + clientSig
			failedReceipts = append(failedReceipts, v)
			failedTickets = append(failedTickets, h)
		}
	}

	// Print results
	if !cfg.Silent {
		fmt.Printf("Votes succeeded: %v\n", len(br.Receipts)-len(failedReceipts))
		fmt.Printf("Votes failed   : %v\n", len(failedReceipts))
		for i, v := range failedReceipts {
			fmt.Printf("Failed vote    : %v %v\n", failedTickets[i], v.ErrorContext)
		}
	}

	return nil
}

// voteBallotHelpMsg is the help command message.
const voteBallotHelpMsg = `voteballot "token" "voteid"

Cast ticket votes for a proposal. This command will only work when on testnet
and when running dcrwallet locally on the default port.

Arguments:
1. token       (string, optional)   Proposal censorship token
2. voteid      (string, optional)   A single word identifying vote (e.g. yes)
`
