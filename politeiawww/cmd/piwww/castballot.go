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

// castBallotCmd casts a ballot of votes for the specified proposal.
type castBallotCmd struct {
	Args struct {
		Token  string `positional-arg-name:"token"`
		VoteID string `positional-arg-name:"voteid"`
	} `positional-args:"true" required:"true"`
	Password string `long:"password" optional:"true"`
}

// Execute executes the castBallotCmd command.
//
// This function satisfies the go-flags Commander interface.
func (c *castBallotCmd) Execute(args []string) error {
	token := c.Args.Token
	voteID := c.Args.VoteID

	// Get vote details
	vr, err := client.Votes(pi.Votes{
		Tokens: []string{token},
	})
	if err != nil {
		return fmt.Errorf("Votes: %v", err)
	}
	pv, ok := vr.Votes[token]
	if !ok {
		return fmt.Errorf("proposal not found: %v", token)
	}
	if pv.Vote == nil {
		return fmt.Errorf("vote hasn't started yet")
	}

	// Verify provided vote ID
	var voteBit string
	for _, option := range pv.Vote.Params.Options {
		if voteID == option.ID {
			voteBit = strconv.FormatUint(option.Bit, 16)
			break
		}
	}
	if voteBit == "" {
		return fmt.Errorf("vote id not found: %v", voteID)
	}

	// Connect to user's wallet
	err = client.LoadWalletClient()
	if err != nil {
		return fmt.Errorf("LoadWalletClient: %v", err)
	}
	defer client.Close()

	// Get the user's tickets that are eligible to vote
	ticketPool, err := convertTicketHashes(pv.Vote.EligibleTickets)
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
		return fmt.Errorf("user has no eligible tickets")
	}

	// Compile the ticket hashes of the user's eligible tickets
	eligibleTickets := make([]string, 0, len(ctr.TicketAddresses))
	for _, v := range ctr.TicketAddresses {
		h, err := chainhash.NewHash(v.Ticket)
		if err != nil {
			return fmt.Errorf("NewHash %x: %v", v.Ticket, err)
		}
		eligibleTickets = append(eligibleTickets, h.String())
	}

	// The next step is to have the user's wallet sign the proposal
	// votes for each ticket. The password wallet is needed for this.
	var passphrase []byte
	if c.Password != "" {
		// Password was provided
		passphrase = []byte(c.Password)
	} else {
		// Prompt user for password
		for len(passphrase) == 0 {
			fmt.Printf("Enter the private passphrase of your wallet: ")
			pass, err := terminal.ReadPassword(int(os.Stdin.Fd()))
			if err != nil {
				return err
			}
			fmt.Printf("\n")
			passphrase = bytes.TrimSpace(pass)
		}
	}

	// Sign eligible tickets with vote preference
	messages := make([]*walletrpc.SignMessagesRequest_Message, 0,
		len(eligibleTickets))
	for i, v := range ctr.TicketAddresses {
		// ctr.TicketAddresses and eligibleTickets share the same ordering
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
	for i, r := range sigs.Replies {
		if r.Error != "" {
			return fmt.Errorf("vote signature failed for ticket %v: %v",
				eligibleTickets[i], err)
		}
	}

	// Setup ballot request
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
	cb := pi.CastBallot{
		Votes: votes,
	}

	// Send ballot request
	cbr, err := client.CastBallot(cb)
	if err != nil {
		return fmt.Errorf("CastBallot: %v", err)
	}

	// Get the server pubkey so that we can validate the receipts.
	version, err := client.Version()
	if err != nil {
		return fmt.Errorf("Version: %v", err)
	}
	serverID, err := util.IdentityFromString(version.PubKey)
	if err != nil {
		return err
	}

	// Check for any failed votes. Vote receipts don't include the
	// ticket hash so in order to associate a failed receipt with a
	// specific ticket, we need  to lookup the ticket hash and store
	// it separately.
	failedReceipts := make([]pi.CastVoteReply, 0, len(cbr.Receipts))
	failedTickets := make([]string, 0, len(eligibleTickets))
	for i, v := range cbr.Receipts {
		// Lookup ticket hash. br.Receipts and eligibleTickets use the
		// same ordering
		h := eligibleTickets[i]

		// Check for vote error
		if v.ErrorContext != "" {
			failedReceipts = append(failedReceipts, v)
			failedTickets = append(failedTickets, h)
			continue
		}

		// Verify receipts
		sig, err := identity.SignatureFromString(v.Receipt)
		if err != nil {
			fmt.Printf("Failed to decode receipt: %v\n", v.Ticket)
			continue
		}
		clientSig := votes[i].Signature
		if !serverID.VerifyMessage([]byte(clientSig), *sig) {
			fmt.Printf("Failed to verify receipt: %v", v.Ticket)
			continue
		}
	}

	// Print results
	if !cfg.Silent {
		fmt.Printf("Votes succeeded: %v\n", len(cbr.Receipts)-len(failedReceipts))
		fmt.Printf("Votes failed   : %v\n", len(failedReceipts))
		for i, v := range failedReceipts {
			fmt.Printf("Failed vote    : %v %v\n", failedTickets[i], v.ErrorContext)
		}
	}

	return nil
}

// castBallotHelpMsg is the help command message.
const castBallotHelpMsg = `castballot "token" "voteid"

Cast a ballot of ticket votes for a proposal. This command will only work when
on testnet and when running dcrwallet locally on the default port.

Arguments:
1. token   (string, optional)  Proposal censorship token
2. voteid  (string, optional)  Vote option ID (e.g. yes)

Flags:
  --password  (string, optional)  Wallet password. You will be prompted for the
                                  password if one is not provided.
`
