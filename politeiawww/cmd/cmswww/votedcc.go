// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"

	v1 "github.com/decred/politeia/politeiawww/api/cms/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// VoteDCCCmd allows a user to vote for a DCC proposal during an all contractor vote.
type VoteDCCCmd struct {
	Args struct {
		Vote  string `positional-arg-name:"vote"`
		Token string `positional-arg-name:"token"`
	} `positional-args:"true" required:"true"`
}

// Execute executes the support DCC command.
func (cmd *VoteDCCCmd) Execute(args []string) error {
	token := cmd.Args.Token
	vote := cmd.Args.Vote

	voteDetails, err := client.VoteDetailsDCC(v1.VoteDetails{Token: token})
	if err != nil {
		return fmt.Errorf("error retreiving vote details: %v", err)
	}
	var jsonVote v1.Vote
	err = json.Unmarshal([]byte(voteDetails.Vote), &jsonVote)
	if err != nil {
		return fmt.Errorf("error retreiving vote details: %v", err)
	}

	voteBits := ""
	validChoices := ""
	for i, option := range jsonVote.Options {
		if i != len(jsonVote.Options)-1 {
			validChoices += option.Id + "/"
		} else {
			validChoices += option.Id
		}
		if vote == option.Id {
			voteBits = strconv.FormatUint(option.Bits, 16)
		}
	}

	if voteBits == "" {
		return fmt.Errorf("invalid request: choose one: %v", validChoices)
	}

	if token == "" {
		return fmt.Errorf("invalid request: you must specify dcc " +
			"token")
	}

	// Check for user identity
	if cfg.Identity == nil {
		return shared.ErrUserIdentityNotFound
	}

	lr, err := client.Me()
	if err != nil {
		return err
	}

	sig := cfg.Identity.SignMessage([]byte(token + voteBits + lr.UserID))
	sd := v1.CastVote{
		VoteBit:   voteBits,
		Token:     token,
		UserID:    lr.UserID,
		PublicKey: hex.EncodeToString(cfg.Identity.Public.Key[:]),
		Signature: hex.EncodeToString(sig[:]),
	}

	// Print request details
	err = shared.PrintJSON(sd)
	if err != nil {
		return err
	}

	// Send request
	sdr, err := client.CastVoteDCC(sd)
	if err != nil {
		return fmt.Errorf("VoteDCC: %v", err)
	}

	// Print response details
	err = shared.PrintJSON(sdr)
	if err != nil {
		return err
	}

	return nil
}
