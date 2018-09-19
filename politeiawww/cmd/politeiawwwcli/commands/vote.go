package commands

import (
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrwallet/rpc/walletrpc"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/util"
)

type VoteCmd struct {
	Args struct {
		Token  string `positional-arg-name:"token" description:"Proposal censorship token"`
		VoteID string `positional-arg-name:"voteid" description:"A single unique word identifying the vote (e.g. yes)"`
	} `positional-args:"true" required:"true"`
}

func (cmd *VoteCmd) Execute(args []string) error {
	token := cmd.Args.Token
	voteID := cmd.Args.VoteID

	// Connet to user's wallet
	err := c.LoadWalletClient()
	if err != nil {
		return fmt.Errorf("LoadWalletClient: %v", err)
	}

	// Get server public key
	vr, err := c.Version()
	if err != nil {
		return fmt.Errorf("Version: %v", err)
	}

	serverID, err := util.IdentityFromString(vr.PubKey)
	if err != nil {
		return err
	}

	// Get all active proposal votes
	avr, err := c.ActiveVotes()
	if err != nil {
		return fmt.Errorf("ActiveVotes: %v", err)
	}

	// Find the proposal that the user wants to vote on
	var pvt *v1.ProposalVoteTuple
	for _, v := range avr.Votes {
		if token == v.Proposal.CensorshipRecord.Token {
			pvt = &v
			break
		}
	}

	if pvt == nil {
		return fmt.Errorf("proposal not found: %v", token)
	}

	// Ensure that the passed in voteID is one of the
	// proposal's voting options and save the vote bits
	var voteBits string
	for _, option := range pvt.StartVote.Vote.Options {
		if voteID == option.Id {
			voteBits = strconv.FormatUint(option.Bits, 16)
			break
		}
	}

	if voteBits == "" {
		return fmt.Errorf("vote id not found: %v", voteID)
	}

	// Find user's tickets that are eligible to vote on this
	// proposal
	ticketPool, err := ConvertTicketHashes(pvt.StartVoteReply.EligibleTickets)
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
		return fmt.Errorf("user has no eligible tickets: %v",
			pvt.StartVote.Vote.Token)
	}

	// Create slice of hexidecimal ticket hashes to represent
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
	passphrase, err := PromptPassphrase()
	if err != nil {
		return fmt.Errorf("PromptPassphrase: %v", err)
	}

	// Sign eligible tickets with vote preference
	messages := make([]*walletrpc.SignMessagesRequest_Message, 0,
		len(eligibleTickets))
	for i, v := range ctr.TicketAddresses {
		// ctr.TicketAddresses and eligibleTickets use the same index
		msg := token + eligibleTickets[i] + voteBits
		messages = append(messages, &walletrpc.SignMessagesRequest_Message{
			Address: v.Address,
			Message: msg,
		})
	}

	sigs, err := c.SignMessages(&walletrpc.SignMessagesRequest{
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
	votes := make([]v1.CastVote, 0, len(eligibleTickets))
	for i, ticket := range eligibleTickets {
		// eligibleTickets and sigs use the same index
		votes = append(votes, v1.CastVote{
			Token:     token,
			Ticket:    ticket,
			VoteBit:   voteBits,
			Signature: hex.EncodeToString(sigs.Replies[i].Signature),
		})
	}

	// Cast proposal votes
	br, err := c.CastVotes(&v1.Ballot{
		Votes: votes,
	})
	if err != nil {
		return fmt.Errorf("CastVotes: %v", err)
	}

	// Check for any failed votes. Vote receipts don't include
	// the ticket hash so in order to associate a failed
	// receipt with a specific ticket, we need  to lookup the
	// ticket hash and store it seperately.
	failedReceipts := make([]v1.CastVoteReply, 0, len(br.Receipts))
	failedTickets := make([]string, 0, len(eligibleTickets))
	for i, v := range br.Receipts {
		// Lookup ticket hash
		// br.Receipts and eligibleTickets use the same index
		h := eligibleTickets[i]

		// Check for voting error
		if v.Error != "" {
			failedReceipts = append(failedReceipts, v)
			failedTickets = append(failedTickets, h)
			continue
		}

		// Validate server signature
		sig, err := identity.SignatureFromString(v.Signature)
		if err != nil {
			v.Error = err.Error()
			failedReceipts = append(failedReceipts, v)
			failedTickets = append(failedTickets, h)
			continue
		}

		if !serverID.VerifyMessage([]byte(v.ClientSignature), *sig) {
			v.Error = "Could not verify receipt " + v.ClientSignature
			failedReceipts = append(failedReceipts, v)
			failedTickets = append(failedTickets, h)
		}
	}

	// Print results
	fmt.Printf("Votes succeeded: %v\n", len(br.Receipts)-len(failedReceipts))
	fmt.Printf("Votes failed   : %v\n", len(failedReceipts))
	for i, v := range failedReceipts {
		fmt.Printf("Failed vote    : %v %v\n", failedTickets[i], v.Error)
	}

	return nil
}
