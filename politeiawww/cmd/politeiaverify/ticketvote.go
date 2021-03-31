// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/decred/politeia/politeiad/backendv2/tstorebe/tstore"
	tkplugin "github.com/decred/politeia/politeiad/plugins/ticketvote"
	tkv1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
	"github.com/decred/politeia/politeiawww/client"
)

// votesBundle represents the bundle that is downloaded from politeiagui for
// DCR ticket votes.
type votesBundle struct {
	Auths           []tkv1.AuthDetails     `json:"auths,omitempty"`
	Details         *tkv1.VoteDetails      `json:"details,omitempty"`
	Votes           []tkv1.CastVoteDetails `json:"votes,omitempty"`
	ServerPublicKey string                 `json:"serverpublickey"`
}

// verifyVotesBundle takes the filepath of a votes bundle and verifies the
// contents of the file. This includes verifying all signatures of the vote
// authorizations, vote details, and cast votes. The cast votes are checked
// against the eligible tickets to ensure all cast votes are valid and are not
// duplicates.
func verifyVotesBundle(fp string) error {
	// Decode votes bundle
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		return err
	}
	var vb votesBundle
	err = json.Unmarshal(b, &vb)
	if err != nil {
		return fmt.Errorf("could not unmarshal votes bundle: %v", err)
	}
	if len(vb.Auths) == 0 {
		return fmt.Errorf("vote has not been authorized yet; nothing to verify")
	}

	fmt.Printf("Token            : %v\n", vb.Auths[0].Token)
	fmt.Printf("Server public key: %v\n", vb.ServerPublicKey)
	fmt.Printf("\n")

	// Verify vote authorization signatures
	for _, v := range vb.Auths {
		fmt.Printf("Auth action : %v\n", v.Action)
		fmt.Printf("  Public key: %v\n", v.PublicKey)
		fmt.Printf("  Signature : %v\n", v.Signature)
		fmt.Printf("  Receipt   : %v\n", v.Receipt)
		err = client.AuthDetailsVerify(v, vb.ServerPublicKey)
		if err != nil {
			return err
		}
	}

	fmt.Printf("Authorization signatures and receipts verified!\n")
	fmt.Printf("\n")

	// Verify the vote details signature
	if vb.Details == nil {
		return fmt.Errorf("vote has not been started; nothing else to verify")
	}
	fmt.Printf("Vote details\n")
	fmt.Printf("  Public key: %v\n", vb.Details.PublicKey)
	fmt.Printf("  Signature : %v\n", vb.Details.Signature)

	err = client.VoteDetailsVerify(*vb.Details)
	if err != nil {
		return err
	}

	fmt.Printf("Vote details signature verified!\n")
	fmt.Printf("\n")

	// Verify cast votes. This includes verifying the cast vote
	// receipt, verifying that the ticket is eligible to vote, and
	// verifying that the vote is not a duplicate.
	var (
		eligible = make(map[string]struct{}, len(vb.Details.EligibleTickets))
		dups     = make(map[string]struct{}, len(vb.Votes))

		notEligible = make([]string, 0, 256)
		duplicates  = make([]string, 0, 256)
	)
	for _, v := range vb.Details.EligibleTickets {
		eligible[v] = struct{}{}
	}

	fmt.Printf("Votes cast: %v/%v\n", len(vb.Votes), len(eligible))

	for _, v := range vb.Votes {
		err := client.CastVoteDetailsVerify(v, vb.ServerPublicKey)
		if err != nil {
			return fmt.Errorf("could not verify vote %v: %v",
				v.Ticket, err)
		}
		_, ok := eligible[v.Ticket]
		if !ok {
			// This ticket is not eligible to vote
			notEligible = append(notEligible, v.Ticket)
		}
		_, ok = dups[v.Ticket]
		if ok {
			// This vote is a duplicate
			duplicates = append(duplicates, v.Ticket)
		}
		dups[v.Ticket] = struct{}{}
	}
	if len(notEligible) > 0 || len(duplicates) > 0 {
		return fmt.Errorf("cast vote validation failed: not eligible %v, "+
			"duplicates %v", notEligible, duplicates)
	}

	fmt.Printf("Cast votes verified!\n")
	fmt.Printf("All cast votes have been checked for eligibility, that " +
		"the receipt signature is valid, and that there are no duplicates.\n")

	return nil
}

// verifyVoteTimestamps takes the filepath of vote timestamps and verifies the
// validity of all timestamps included in the ticketvote v1 TimestampsReply.
func verifyVoteTimestamps(fp string) error {
	// Decode timestamps reply
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		return err
	}
	var tr tkv1.TimestampsReply
	err = json.Unmarshal(b, &tr)
	if err != nil {
		return err
	}

	// Verify authorization timestamps
	if len(tr.Auths) == 0 {
		return fmt.Errorf("vote has not been authorized; nothing to verify")
	}

	fmt.Printf("Vote authorizations: %v\n", len(tr.Auths))

	for i, v := range tr.Auths {
		err := client.TicketVoteTimestampVerify(v)
		if err != nil {
			return fmt.Errorf("unable to verify authorization timestamp %v: %v",
				i, err)
		}
	}

	fmt.Printf("Vote authorization timestamps verified!\n")

	// Verify vote details timestamp
	if tr.Details == nil {
		return fmt.Errorf("vote has not been started; nothing else to verify")
	}
	err = client.TicketVoteTimestampVerify(*tr.Details)
	if err != nil {
		return fmt.Errorf("unable to verify vote details timestamp: %v", err)
	}

	fmt.Printf("Vote details timestamp verified!\n")

	// Verify cast vote timestamps
	notTimestamped := make([]string, 0, len(tr.Votes))
	for i, v := range tr.Votes {
		err = client.TicketVoteTimestampVerify(v)
		switch err {
		case nil:
			// Timestamp verified. Check the next one.
			continue
		case tstore.ErrNotTimestamped:
			// This ticket has not been timestamped yet. Continue to the
			// code below so that the ticket hash gets printed.
		default:
			// An unexpected error occurred
			return fmt.Errorf("could not verify cast vote timestamp %v: %v",
				i, err)
		}

		// This vote has not been timestamped yet. Decode the cast vote
		// and save the ticket hash.
		var cvd tkplugin.CastVoteDetails
		err = json.Unmarshal([]byte(v.Data), &cvd)
		if err != nil {
			return fmt.Errorf("could not unmarshal cast vote: %v", err)
		}
		notTimestamped = append(notTimestamped, cvd.Ticket)
	}

	fmt.Printf("Total votes        : %v\n", len(tr.Votes))
	fmt.Printf("Not timestamped yet: %v\n", len(notTimestamped))
	for _, v := range notTimestamped {
		fmt.Printf("  %v\n", v)
	}
	fmt.Printf("Cast vote timestamps verified!")

	return nil
}
