// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"

	"decred.org/dcrwallet/rpc/walletrpc"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	tkv1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
	"github.com/decred/politeia/util"
)

// cmdCastBallot casts a ballot of votes.
type cmdCastBallot struct {
	Args struct {
		Token  string `positional-arg-name:"token"`
		VoteID string `positional-arg-name:"voteid"`
	} `positional-args:"true" required:"true"`
	Password string `long:"password" optional:"true"`
}

// Execute executes the cmdCastBallot command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdCastBallot) Execute(args []string) error {
	// Unpack args
	var (
		token  = c.Args.Token
		voteID = c.Args.VoteID
	)

	// Setup politeiawww client
	opts := pclient.Opts{
		HTTPSCert: cfg.HTTPSCert,
		Verbose:   cfg.Verbose,
		RawJSON:   cfg.RawJSON,
	}
	pc, err := pclient.New(cfg.Host, opts)
	if err != nil {
		return err
	}

	// Setup dcrwallet client
	ctx := context.Background()
	wc, err := newDcrwalletClient(cfg.WalletHost, cfg.WalletCert,
		cfg.ClientCert, cfg.ClientKey)
	if err != nil {
		return err
	}
	defer wc.conn.Close()

	// Get vote details
	d := tkv1.Details{
		Token: token,
	}
	dr, err := pc.TicketVoteDetails(d)
	if err != nil {
		return err
	}
	if dr.Vote == nil {
		return fmt.Errorf("vote not started")
	}
	voteDetails := dr.Vote

	// Verify provided vote ID
	var voteBit string
	for _, option := range voteDetails.Params.Options {
		if voteID == option.ID {
			voteBit = strconv.FormatUint(option.Bit, 16)
			break
		}
	}
	if voteBit == "" {
		return fmt.Errorf("vote id not found: %v", voteID)
	}

	// Get the user's tickets that are eligible to vote
	ticketPool := make([][]byte, 0, len(voteDetails.EligibleTickets))
	for _, v := range voteDetails.EligibleTickets {
		h, err := chainhash.NewHashFromStr(v)
		if err != nil {
			return err
		}
		ticketPool = append(ticketPool, h[:])
	}
	ct := walletrpc.CommittedTicketsRequest{
		Tickets: ticketPool,
	}
	ctr, err := wc.wallet.CommittedTickets(ctx, &ct)
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
	// votes for each ticket. The wallet password is needed for this.
	var passphrase []byte
	if c.Password != "" {
		// Password was provided
		passphrase = []byte(c.Password)
	} else {
		// Prompt user for password
		passphrase, err = promptWalletPassword()
		if err != nil {
			return err
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
	sm := walletrpc.SignMessagesRequest{
		Passphrase: passphrase,
		Messages:   messages,
	}
	sigs, err := wc.wallet.SignMessages(ctx, &sm)
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
	votes := make([]tkv1.CastVote, 0, len(eligibleTickets))
	for i, ticket := range eligibleTickets {
		// eligibleTickets and sigs use the same index
		votes = append(votes, tkv1.CastVote{
			Token:     token,
			Ticket:    ticket,
			VoteBit:   voteBit,
			Signature: hex.EncodeToString(sigs.Replies[i].Signature),
		})
	}
	cb := tkv1.CastBallot{
		Votes: votes,
	}

	// Send ballot request
	cbr, err := pc.TicketVoteCastBallot(cb)
	if err != nil {
		return err
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
	failedReceipts := make([]tkv1.CastVoteReply, 0, len(cbr.Receipts))
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
			printf("Failed to decode receipt: %v\n", v.Ticket)
			continue
		}
		clientSig := votes[i].Signature
		if !serverID.VerifyMessage([]byte(clientSig), *sig) {
			printf("Failed to verify receipt: %v", v.Ticket)
			continue
		}
	}

	// Print results
	printf("Votes succeeded: %v\n", len(cbr.Receipts)-len(failedReceipts))
	printf("Votes failed   : %v\n", len(failedReceipts))
	for i, v := range failedReceipts {
		printf("Failed vote    : %v %v\n", failedTickets[i], v.ErrorContext)
	}

	return nil
}

// castBallotHelpMsg is printed to stdout by the help command.
const castBallotHelpMsg = `castballot "token" "voteid"

Cast a ballot of dcr ticket votes. This command will only work when on testnet
and when running dcrwallet locally on the default port.

Arguments:
1. token   (string, optional)  Proposal censorship token
2. voteid  (string, optional)  Vote option ID (e.g. yes)

Flags:
 --password  (string, optional)  Wallet password. You will be prompted for the
                                 password if one is not provided.
`
