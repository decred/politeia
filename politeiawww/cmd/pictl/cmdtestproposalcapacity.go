// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"strconv"

	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
	"github.com/decred/politeia/util"
)

type cmdTestProposalCapacity struct {
	Args struct {
		AdminEmail    string `positional-arg-name:"adminemail" required:"true"`
		AdminPassword string `positional-arg-name:"adminpassword" required:"true"`
	} `positional-args:"true"`
}

// TODO this is temp
const randomImages = false

// Execute executes the cmdTestProposalCapacity command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdTestProposalCapacity) Execute(args []string) error {
	const (
		// Test run params
		userCount               = 1
		proposalCount           = 5
		commentsPerProposal     = 100
		commentVotesPerProposal = 1000
	)

	// We don't want the output of individual commands printed.
	cfg.Verbose = false
	cfg.RawJSON = false
	cfg.Silent = true

	// Verify the the provided login credentials are for an admin.
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

	// Verify that the paywall is disabled.
	policyWWW, err := client.Policy()
	if err != nil {
		return err
	}
	if policyWWW.PaywallEnabled {
		return fmt.Errorf("paywall is not disabled")
	}

	// Setup users
	users := make([]user, 0, userCount)
	for i := 0; i < userCount; i++ {
		log := fmt.Sprintf("Creating user %v/%v", i+1, userCount)
		printInPlace(log)

		u, err := userNewRandom(policyWWW.MaxUsernameLength)
		if err != nil {
			return err
		}

		users = append(users, *u)
	}
	fmt.Printf("\n")

	// Setup proposals
	var (
		statusUnreviewed       = "unreviewed"
		statusUnvettedCensored = "unvetted-censored"
		statusPublic           = "public"
		statusVettedCensored   = "vetted-cesored"
		statusAbandoned        = "abandoned"

		statuses = []string{
			statusUnreviewed,
			statusUnvettedCensored,
			statusPublic,
			statusVettedCensored,
			statusAbandoned,
		}

		// These are used to track the number of proposals that are
		// created for each status.
		countUnreviewed       int
		countUnvettedCensored int
		countPublic           int
		countVettedCensored   int
		countAbandoned        int
	)
	for i := 0; i < proposalCount; i++ {
		// Select a random user
		r := rand.Intn(len(users))
		u := users[r]

		// Select a random status. This will be the ending status of
		// the proposal.
		r = rand.Intn(len(statuses))
		s := statuses[r]

		log := fmt.Sprintf("Submitting proposal %v/%v: %-17v",
			i+1, proposalCount, s)
		printInPlace(log)

		// Create proposal
		switch s {
		case statusUnreviewed:
			_, err = proposalUnreviewed(u)
			if err != nil {
				return err
			}
			countUnreviewed++
		case statusUnvettedCensored:
			_, err = proposalUnvettedCensored(u, admin)
			if err != nil {
				return err
			}
			countUnvettedCensored++
		case statusPublic:
			_, err = proposalPublic(u, admin)
			if err != nil {
				return err
			}
			countPublic++
		case statusVettedCensored:
			_, err = proposalVettedCensored(u, admin)
			if err != nil {
				return err
			}
			countVettedCensored++
		case statusAbandoned:
			_, err = proposalAbandoned(u, admin)
			if err != nil {
				return err
			}
			countAbandoned++
		default:
			return fmt.Errorf("invalid status %v", s)
		}
	}
	fmt.Printf("\n")

	// Setup comments
	// Setup comment votes

	_ = commentsPerProposal
	_ = commentVotesPerProposal

	return nil
}

type user struct {
	Email    string
	Password string
	Username string
}

// userNew creates a new user.
//
// This function returns with the user logged out.
func userNew(email, username, password string) (*user, error) {
	// Create user
	c := userNewCmd{
		Verify: true,
	}
	c.Args.Email = email
	c.Args.Username = username
	c.Args.Password = password
	err := c.Execute(nil)
	if err != nil {
		return nil, fmt.Errorf("userNewCmd: %v", err)
	}

	// Log out user
	err = userLogout()
	if err != nil {
		return nil, err
	}

	return &user{
		Email:    email,
		Username: username,
		Password: password,
	}, nil
}

// userNewRandom creates a new user with random credentials.
//
// This function returns with the user logged out.
func userNewRandom(usernameLength uint) (*user, error) {
	// Hex encoding creates 2x the number of characters as bytes.
	// Ex: 4 bytes will results in a 8 character hex string.
	b, err := util.Random(int(usernameLength / uint(2)))
	if err != nil {
		return nil, err
	}
	var (
		r        = hex.EncodeToString(b)
		email    = r + "@example.com"
		username = r
		password = r
	)
	return userNew(email, username, password)
}

// userLogin logs in the provided user.
func userLogin(u user) error {
	c := shared.LoginCmd{}
	c.Args.Email = u.Email
	c.Args.Password = u.Password
	err := c.Execute(nil)
	if err != nil {
		return fmt.Errorf("LoginCmd: %v", err)
	}
	return nil
}

// userLogout logs out any logged in user.
func userLogout() error {
	c := shared.LogoutCmd{}
	err := c.Execute(nil)
	if err != nil {
		return fmt.Errorf("LogoutCmd: %v", err)
	}
	return nil
}

// proposalUnreviewed creates a new proposal and leaves its status as
// unreviewed.
//
// This function returns with the user logged out.
func proposalUnreviewed(u user) (*rcv1.Record, error) {
	// Login user
	err := userLogin(u)
	if err != nil {
		return nil, err
	}

	// Submit new proposal
	cn := cmdProposalNew{
		Random:       true,
		RandomImages: randomImages,
	}
	r, err := proposalNew(&cn)
	if err != nil {
		return nil, fmt.Errorf("cmdProposalNew: %v", err)
	}

	// Edit the proposal
	ce := cmdProposalEdit{
		Unvetted:     true,
		Random:       true,
		RandomImages: randomImages,
	}
	ce.Args.Token = r.CensorshipRecord.Token
	r, err = proposalEdit(&ce)
	if err != nil {
		return nil, fmt.Errorf("cmdProposalEdit: %v", err)
	}

	// Logout user
	err = userLogout()
	if err != nil {
		return nil, err
	}

	return r, nil
}

// proposalUnvettedCensored creates a new proposal then censors the proposal.
//
// This function returns with all users logged out.
func proposalUnvettedCensored(u user, admin user) (*rcv1.Record, error) {
	// Setup an unvetted proposal
	r, err := proposalUnreviewed(u)
	if err != nil {
		return nil, err
	}

	// Login admin
	err = userLogin(admin)
	if err != nil {
		return nil, err
	}

	// Censor the proposal
	cs := cmdProposalSetStatus{
		Unvetted: true,
	}
	cs.Args.Token = r.CensorshipRecord.Token
	cs.Args.Status = strconv.Itoa(int(rcv1.RecordStatusCensored))
	cs.Args.Reason = "Violates proposal rules."
	cs.Args.Version = r.Version
	r, err = proposalSetStatus(&cs)
	if err != nil {
		return nil, fmt.Errorf("cmdProposalSetStatus: %v", err)
	}

	// Logout admin
	err = userLogout()
	if err != nil {
		return nil, err
	}

	return r, nil
}

// proposalPublic creates and new proposal then makes the proposal public.
//
// This function returns with all users logged out.
func proposalPublic(u user, admin user) (*rcv1.Record, error) {
	// Setup an unvetted proposal
	r, err := proposalUnreviewed(u)
	if err != nil {
		return nil, err
	}

	// Login admin
	err = userLogin(admin)
	if err != nil {
		return nil, err
	}

	// Make the proposal public
	cs := cmdProposalSetStatus{
		Unvetted: true,
	}
	cs.Args.Token = r.CensorshipRecord.Token
	cs.Args.Status = strconv.Itoa(int(rcv1.RecordStatusPublic))
	cs.Args.Version = r.Version
	r, err = proposalSetStatus(&cs)
	if err != nil {
		return nil, fmt.Errorf("cmdProposalSetStatus: %v", err)
	}

	// Logout admin
	err = userLogout()
	if err != nil {
		return nil, err
	}

	// Login user
	err = userLogin(u)
	if err != nil {
		return nil, err
	}

	// Edit the proposal
	ce := cmdProposalEdit{
		Unvetted:     false,
		Random:       true,
		RandomImages: randomImages,
	}
	ce.Args.Token = r.CensorshipRecord.Token
	r, err = proposalEdit(&ce)
	if err != nil {
		return nil, fmt.Errorf("cmdProposalEdit: %v", err)
	}

	// Logout user
	err = userLogout()
	if err != nil {
		return nil, err
	}

	return r, nil
}

// proposalVettedCensored creates a new proposal, makes the proposal public,
// then censors the proposal.
//
// This function returns with all users logged out.
func proposalVettedCensored(u user, admin user) (*rcv1.Record, error) {
	// Create a public proposal
	r, err := proposalPublic(u, admin)
	if err != nil {
		return nil, err
	}

	// Login admin
	err = userLogin(admin)
	if err != nil {
		return nil, err
	}

	// Censor the proposal
	cs := cmdProposalSetStatus{
		Unvetted: false,
	}
	cs.Args.Token = r.CensorshipRecord.Token
	cs.Args.Status = strconv.Itoa(int(rcv1.RecordStatusCensored))
	cs.Args.Reason = "Violates proposal rules."
	cs.Args.Version = r.Version
	r, err = proposalSetStatus(&cs)
	if err != nil {
		return nil, fmt.Errorf("cmdProposalSetStatus: %v", err)
	}

	// Logout admin
	err = userLogout()
	if err != nil {
		return nil, err
	}

	return r, nil
}

// proposalAbandoned creates a new proposal, makes the proposal public,
// then abandones the proposal.
//
// This function returns with all users logged out.
func proposalAbandoned(u user, admin user) (*rcv1.Record, error) {
	// Create a public proposal
	r, err := proposalPublic(u, admin)
	if err != nil {
		return nil, err
	}

	// Login admin
	err = userLogin(admin)
	if err != nil {
		return nil, err
	}

	// Abandone the proposal
	cs := cmdProposalSetStatus{
		Unvetted: false,
	}
	cs.Args.Token = r.CensorshipRecord.Token
	cs.Args.Status = strconv.Itoa(int(rcv1.RecordStatusArchived))
	cs.Args.Reason = "No activity from author in 3 weeks."
	cs.Args.Version = r.Version
	r, err = proposalSetStatus(&cs)
	if err != nil {
		return nil, fmt.Errorf("cmdProposalSetStatus: %v", err)
	}

	// Logout admin
	err = userLogout()
	if err != nil {
		return nil, err
	}

	return r, nil
}
