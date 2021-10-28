// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"fmt"
	"strconv"

	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
	"github.com/decred/politeia/politeiawww/cmd/shared"
	"github.com/decred/politeia/util"
)

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
func userNewRandom() (*user, error) {
	// Hex encoding creates 2x the number of characters as bytes.
	// Ex: 4 bytes will results in a 8 character hex string.
	b, err := util.Random(5)
	if err != nil {
		return nil, err
	}
	var (
		r        = hex.EncodeToString(b)
		email    = r + "@example.com"
		username = "user_" + r
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

// proposalOpts includes all the possible configurations which can be used
// when creating a new proposal using the cmdProposalNew command.
type proposalOpts struct {
	Name      string
	LinkTo    string
	LinkBy    string
	Amount    uint64
	StartDate string
	EndDate   string
	Domain    string

	RFP bool

	Random bool

	RandomImages bool
}

// proposalUnreviewed creates a new proposal and leaves its status as
// unreviewed.
//
// This function returns with the user logged out.
func proposalUnreviewed(u user, opts *proposalOpts) (*rcv1.Record, error) {
	// Login user
	err := userLogin(u)
	if err != nil {
		return nil, err
	}

	// Submit new proposal
	var cn cmdProposalNew
	if opts != nil {
		if opts.Name != "" {
			cn.Name = opts.Name
		}
		if opts.LinkTo != "" {
			cn.LinkTo = opts.LinkTo
		}
		if opts.LinkBy != "" {
			cn.LinkBy = opts.LinkBy
		}
		if opts.Amount != 0 {
			cn.Amount = opts.Amount
		}
		if opts.StartDate != "" {
			cn.StartDate = opts.StartDate
		}
		if opts.EndDate != "" {
			cn.EndDate = opts.EndDate
		}
		if opts.Domain != "" {
			cn.Domain = opts.Domain
		}
		if opts.RFP {
			cn.RFP = opts.RFP
		}
		if opts.Random {
			cn.Random = opts.Random
		}
		if opts.RandomImages {
			cn.RandomImages = opts.RandomImages
		}
	}
	r, err := proposalNew(&cn)
	if err != nil {
		return nil, fmt.Errorf("cmdProposalNew: %v", err)
	}

	// Edit the proposal
	r, err = proposalEditWithOpts(r.CensorshipRecord.Token, opts)
	if err != nil {
		return nil, err
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
func proposalUnvettedCensored(author, admin user, opts *proposalOpts) (*rcv1.Record, error) {
	// Setup an unvetted proposal
	r, err := proposalUnreviewed(author, opts)
	if err != nil {
		return nil, err
	}

	// Login admin
	err = userLogin(admin)
	if err != nil {
		return nil, err
	}

	// Censor the proposal
	cs := cmdProposalSetStatus{}
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

// proposalPublic creates a new proposal then makes it public.
//
// This function returns with all users logged out.
func proposalPublic(author, admin user, opts *proposalOpts) (*rcv1.Record, error) {
	// Setup an unvetted proposal
	r, err := proposalUnreviewed(author, opts)
	if err != nil {
		return nil, err
	}

	// Login admin
	err = userLogin(admin)
	if err != nil {
		return nil, err
	}

	// Make the proposal public
	cs := cmdProposalSetStatus{}
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

	// Login author
	err = userLogin(author)
	if err != nil {
		return nil, err
	}

	// Edit the proposal
	r, err = proposalEditWithOpts(r.CensorshipRecord.Token, opts)
	if err != nil {
		return nil, err
	}

	// Logout author
	err = userLogout()
	if err != nil {
		return nil, err
	}

	return r, nil
}

// proposalEditWithOpts edits a proposal, in addition to the proposal tokens, it
// accepts a pointer to a proposalOpts struct which can be used to configure
// the various arguments and flags of the cmdProposalEdit command.
func proposalEditWithOpts(token string, opts *proposalOpts) (*rcv1.Record, error) {
	var ce cmdProposalEdit
	if opts != nil {
		if opts.Name != "" {
			ce.Name = opts.Name
		}
		if opts.LinkTo != "" {
			ce.LinkTo = opts.LinkTo
		}
		if opts.LinkBy != "" {
			ce.LinkBy = opts.LinkBy
		}
		if opts.Amount != 0 {
			ce.Amount = opts.Amount
		}
		if opts.StartDate != "" {
			ce.StartDate = opts.StartDate
		}
		if opts.EndDate != "" {
			ce.EndDate = opts.EndDate
		}
		if opts.Domain != "" {
			ce.Domain = opts.Domain
		}
		if opts.RFP {
			ce.RFP = opts.RFP
		}
		if opts.Random {
			ce.Random = opts.Random
		}
		if opts.RandomImages {
			ce.RandomImages = opts.RandomImages
		}
	}
	ce.Args.Token = token
	r, err := proposalEdit(&ce)
	if err != nil {
		return nil, fmt.Errorf("cmdProposalEdit: %v", err)
	}

	return r, nil
}

// proposalVettedCensored creates a new proposal, makes the proposal public,
// then censors the proposal.
//
// This function returns with all users logged out.
func proposalVettedCensored(author, admin user, opts *proposalOpts) (*rcv1.Record, error) {
	// Create a public proposal
	r, err := proposalPublic(author, admin, opts)
	if err != nil {
		return nil, err
	}

	// Login admin
	err = userLogin(admin)
	if err != nil {
		return nil, err
	}

	// Censor the proposal
	cs := cmdProposalSetStatus{}
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
func proposalAbandoned(author, admin user, opts *proposalOpts) (*rcv1.Record, error) {
	// Create a public proposal
	r, err := proposalPublic(author, admin, opts)
	if err != nil {
		return nil, err
	}

	// Login admin
	err = userLogin(admin)
	if err != nil {
		return nil, err
	}

	// Abandone the proposal
	cs := cmdProposalSetStatus{}
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

// voteAuthorize authorizes the ticket vote.
//
// This function returns with the user logged out.
func voteAuthorize(author user, token string) error {
	// Login author
	err := userLogin(author)
	if err != nil {
		return err
	}

	// Authorize the voting period
	c := cmdVoteAuthorize{}
	c.Args.Token = token
	err = c.Execute(nil)
	if err != nil {
		return fmt.Errorf("cmdVoteAuthorize: %v", err)
	}

	// Logout author
	err = userLogout()
	if err != nil {
		return err
	}

	return nil
}

// voteStart starts the voting period on a record.
//
// This function returns with the admin logged out.
func voteStart(admin user, token string, duration, quorum, pass uint32) error {
	// Login admin
	err := userLogin(admin)
	if err != nil {
		return err
	}

	// Setup client
	opts := pclient.Opts{
		HTTPSCert:  cfg.HTTPSCert,
		Cookies:    cfg.Cookies,
		HeaderCSRF: cfg.CSRF,
		Verbose:    cfg.Verbose,
		RawJSON:    cfg.RawJSON,
	}
	pc, err := pclient.New(cfg.Host, opts)
	if err != nil {
		return err
	}

	// Start the voting period
	_, err = voteStartStandard(token, duration, quorum, pass, pc)
	if err != nil {
		return err
	}

	// Logout admin
	err = userLogout()
	if err != nil {
		return err
	}

	return nil
}

// voteStartRunoff starts the runoff voting period on a RFP.
//
// This function returns with the admin logged out.
func voteRunoff(admin user, token string, duration, quorum, pass uint32) error {
	// Login admin
	err := userLogin(admin)
	if err != nil {
		return err
	}

	// Setup client
	opts := pclient.Opts{
		HTTPSCert:  cfg.HTTPSCert,
		Cookies:    cfg.Cookies,
		HeaderCSRF: cfg.CSRF,
		Verbose:    cfg.Verbose,
		RawJSON:    cfg.RawJSON,
	}
	pc, err := pclient.New(cfg.Host, opts)
	if err != nil {
		return err
	}

	// Start the runoff voting period
	_, err = voteStartRunoff(token, duration, quorum, pass, pc)
	if err != nil {
		return err
	}

	// Logout admin
	err = userLogout()
	if err != nil {
		return err
	}

	return nil
}
