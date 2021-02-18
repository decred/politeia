// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"strconv"
	"time"

	cmv1 "github.com/decred/politeia/politeiawww/api/comments/v1"
	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
	"github.com/decred/politeia/util"
)

type cmdSeedProposals struct {
	Args struct {
		AdminEmail    string `positional-arg-name:"adminemail" required:"true"`
		AdminPassword string `positional-arg-name:"adminpassword" required:"true"`
		Users         int    `positional-arg-name:"users"`
		Proposals     int    `positional-arg-name:"proposals"`
		CommentVotes  int    `positional-arg-name:"commentvotes"`
	} `positional-args:"true"`

	// IncludeImages is used to include a random number of images when
	// submitting proposals.
	IncludeImages bool `long:"includeimages"`
}

// Execute executes the cmdSeedProposals command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdSeedProposals) Execute(args []string) error {
	fmt.Printf("Warn: this cmd should be run on a clean politeia instance\n")

	// Setup default parameters
	var (
		userCount               = 10
		proposalCount           = 25
		commentsPerProposal     = 100
		commentSize             = 32 // In characters
		commentVotesPerProposal = 500

		includeImages = c.IncludeImages
	)
	if c.Args.Users != 0 {
		userCount = c.Args.Users
	}
	if c.Args.Proposals != 0 {
		proposalCount = c.Args.Proposals
	}
	if c.Args.CommentVotes != 0 {
		commentVotesPerProposal = c.Args.CommentVotes
	}

	// We don't want the output of individual commands printed.
	cfg.Verbose = false
	cfg.RawJSON = false
	cfg.Silent = true

	// User count must be at least 2. A user cannot upvote their own
	// comments so we need at least 1 user to make comments and a
	// second user to upvote the comments.
	if userCount < 2 {
		return fmt.Errorf("user count must be >= 2")
	}

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

		u, err := userNewRandom()
		if err != nil {
			return err
		}

		users = append(users, *u)
	}
	fmt.Printf("\n")

	// Log start time
	fmt.Printf("Start time: %v\n", timestampFromUnix(time.Now().Unix()))

	// Setup proposals
	var (
		statusUnreviewed       = "unreviewed"
		statusUnvettedCensored = "unvetted-censored"
		statusPublic           = "public"
		statusVettedCensored   = "vetted-cesored"
		statusAbandoned        = "abandoned"

		// statuses specifies the statuses that are rotated through when
		// proposals are being submitted. We can increase the proption of
		// proposals that are a specific status by increasing the number
		// of times the status occurs in this array.
		statuses = []string{
			statusPublic,
			statusPublic,
			statusPublic,
			statusPublic,
			statusUnreviewed,
			statusUnvettedCensored,
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

		// public is used to aggregate the tokens of public proposals.
		// These will be used when we add comments to the proposals.
		public = make([]string, 0, proposalCount)
	)
	for i := 0; i < proposalCount; i++ {
		// Select a random user
		r := rand.Intn(len(users))
		u := users[r]

		// Rotate through the statuses
		s := statuses[i%len(statuses)]

		log := fmt.Sprintf("Submitting proposal %v/%v: %v",
			i+1, proposalCount, s)
		printInPlace(log)

		// Create proposal
		switch s {
		case statusUnreviewed:
			_, err = proposalUnreviewed(u, includeImages)
			if err != nil {
				return err
			}
			countUnreviewed++
		case statusUnvettedCensored:
			_, err = proposalUnvettedCensored(u, admin, includeImages)
			if err != nil {
				return err
			}
			countUnvettedCensored++
		case statusPublic:
			r, err := proposalPublic(u, admin, includeImages)
			if err != nil {
				return err
			}
			countPublic++
			public = append(public, r.CensorshipRecord.Token)
		case statusVettedCensored:
			_, err = proposalVettedCensored(u, admin, includeImages)
			if err != nil {
				return err
			}
			countVettedCensored++
		case statusAbandoned:
			_, err = proposalAbandoned(u, admin, includeImages)
			if err != nil {
				return err
			}
			countAbandoned++
		default:
			return fmt.Errorf("invalid status %v", s)
		}
	}
	fmt.Printf("\n")

	// Verify proposal inventory
	var (
		statusesUnvetted = map[rcv1.RecordStatusT]int{
			rcv1.RecordStatusUnreviewed: countUnreviewed,
			rcv1.RecordStatusCensored:   countUnvettedCensored,
		}

		statusesVetted = map[rcv1.RecordStatusT]int{
			rcv1.RecordStatusPublic:   countPublic,
			rcv1.RecordStatusCensored: countVettedCensored,
			rcv1.RecordStatusArchived: countAbandoned,
		}
	)
	for status, count := range statusesUnvetted {
		// Tally up how many records are in the inventory for each
		// status.
		var tally int
		var page uint32 = 1
		for {
			log := fmt.Sprintf("Verifying unvetted inv for status %v, page %v",
				rcv1.RecordStatuses[status], page)
			printInPlace(log)

			tokens, err := invUnvetted(admin, status, page)
			if err != nil {
				return err
			}
			if len(tokens) == 0 {
				// We've reached the end of the inventory
				break
			}
			tally += len(tokens)
			page++
		}
		fmt.Printf("\n")

		// The count might be more than the tally if there were already
		// proposals in the inventory prior to running this command. The
		// tally should never be less than the count.
		if tally < count {
			return fmt.Errorf("unexpected number of proposals in inventory "+
				"for status %v: got %v, want >=%v", rcv1.RecordStatuses[status],
				tally, count)
		}
	}
	for status, count := range statusesVetted {
		// Tally up how many records are in the inventory for each
		// status.
		var tally int
		var page uint32 = 1
		for {
			log := fmt.Sprintf("Verifying vetted inv for status %v, page %v",
				rcv1.RecordStatuses[status], page)
			printInPlace(log)

			tokens, err := inv(rcv1.RecordStateVetted, status, page)
			if err != nil {
				return err
			}
			if len(tokens) == 0 {
				// We've reached the end of the inventory
				break
			}
			tally += len(tokens)
			page++
		}
		fmt.Printf("\n")

		// The count might be more than the tally if there were already
		// proposals in the inventory prior to running this command. The
		// tally should never be less than the count.
		if tally < count {
			return fmt.Errorf("unexpected number of proposals in inventory "+
				"for status %v: got %v, want >=%v", rcv1.RecordStatuses[status],
				tally, count)
		}
	}

	// Users cannot vote on their own comment. Divide the user into two
	// groups. Group 1 will create the comments. Group 2 will vote on
	// the comments.
	users1 := users[:len(users)/2]
	users2 := users[len(users)/2:]

	// Setup comments
	for i, token := range public {
		for j := 0; j < commentsPerProposal; j++ {
			log := fmt.Sprintf("Submitting comments for proposal %v/%v, "+
				"comment %v/%v", i+1, len(public), j+1, commentsPerProposal)
			printInPlace(log)

			// Select a random user
			r := rand.Intn(len(users1))
			u := users1[r]

			// Every 5th comment should be the start of a comment thread, not
			// a reply. All other comments should be replies to a random
			// existing comment.
			var parentID uint32
			switch {
			case j%5 == 0:
				// This should be a parent comment. Keep the parent ID as 0.
			default:
				// Reply to a random comment
				parentID = uint32(rand.Intn(j + 1))
			}

			// Create random comment
			b, err := util.Random(commentSize / 2)
			if err != nil {
				return err
			}
			comment := hex.EncodeToString(b)

			// Submit comment
			err = commentNew(u, token, comment, parentID)
			if err != nil {
				return err
			}
		}
	}
	fmt.Printf("\n")

	// Setup comment votes
	for i, token := range public {
		// Get the number of comments this proposal has
		count, err := commentCountForRecord(token)
		if err != nil {
			return err
		}

		// We iterate through the users and comments sequentially. Trying
		// to vote on comments randomly can cause max vote changes
		// exceeded errors.
		var (
			userIdx   int
			commentID uint32 = 1
		)
		for j := 0; j < commentVotesPerProposal; j++ {
			log := fmt.Sprintf("Submitting comment votes for proposal %v/%v, "+
				"comment %v/%v", i+1, len(public), j+1, commentVotesPerProposal)
			printInPlace(log)

			// Setup the comment ID and the user
			if commentID > count {
				// We've reached the end of the comments. Start back over
				// with a different user.
				userIdx++
				commentID = 1
			}
			if userIdx == len(users2) {
				// We've reached the end of the users. Start back over.
				userIdx = 0
			}
			u := users2[userIdx]

			// Select a random vote preference
			var vote string
			if rand.Intn(100)%2 == 0 {
				vote = strconv.Itoa(int(cmv1.VoteUpvote))
			} else {
				vote = strconv.Itoa(int(cmv1.VoteDownvote))
			}

			// Cast comment vote
			err := commentVote(u, token, commentID, vote)
			if err != nil {
				return err
			}

			// Increment comment ID
			commentID++
		}
	}
	fmt.Printf("\n")

	ts := timestampFromUnix(time.Now().Unix())
	fmt.Printf("Done!\n")
	fmt.Printf("Stop time                 : %v\n", ts)
	fmt.Printf("Users                     : %v\n", userCount)
	fmt.Printf("Proposals                 : %v\n", proposalCount)
	fmt.Printf("Comments per proposal     : %v\n", commentsPerProposal)
	fmt.Printf("Comment votes per proposal: %v\n", commentVotesPerProposal)

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

// proposalUnreviewed creates a new proposal and leaves its status as
// unreviewed.
//
// This function returns with the user logged out.
func proposalUnreviewed(u user, includeImages bool) (*rcv1.Record, error) {
	// Login user
	err := userLogin(u)
	if err != nil {
		return nil, err
	}

	// Submit new proposal
	cn := cmdProposalNew{
		Random:       true,
		RandomImages: includeImages,
	}
	r, err := proposalNew(&cn)
	if err != nil {
		return nil, fmt.Errorf("cmdProposalNew: %v", err)
	}

	// Edit the proposal
	ce := cmdProposalEdit{
		Unvetted:     true,
		Random:       true,
		RandomImages: includeImages,
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
func proposalUnvettedCensored(author, admin user, includeImages bool) (*rcv1.Record, error) {
	// Setup an unvetted proposal
	r, err := proposalUnreviewed(author, includeImages)
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
func proposalPublic(author, admin user, includeImages bool) (*rcv1.Record, error) {
	// Setup an unvetted proposal
	r, err := proposalUnreviewed(author, includeImages)
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

	// Login author
	err = userLogin(author)
	if err != nil {
		return nil, err
	}

	// Edit the proposal
	ce := cmdProposalEdit{
		Unvetted:     false,
		Random:       true,
		RandomImages: includeImages,
	}
	ce.Args.Token = r.CensorshipRecord.Token
	r, err = proposalEdit(&ce)
	if err != nil {
		return nil, fmt.Errorf("cmdProposalEdit: %v", err)
	}

	// Logout author
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
func proposalVettedCensored(author, admin user, includeImages bool) (*rcv1.Record, error) {
	// Create a public proposal
	r, err := proposalPublic(author, admin, includeImages)
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
func proposalAbandoned(author, admin user, includeImages bool) (*rcv1.Record, error) {
	// Create a public proposal
	r, err := proposalPublic(author, admin, includeImages)
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

// inv returns a page of tokens for a record status.
func inv(state string, status rcv1.RecordStatusT, page uint32) ([]string, error) {
	// Setup command
	c := cmdProposalInv{}
	switch state {
	case rcv1.RecordStateUnvetted:
		c.Unvetted = true
	case rcv1.RecordStateVetted:
		// Do nothing
	default:
		return nil, fmt.Errorf("invalid state")
	}
	c.Args.Status = strconv.Itoa(int(status))
	c.Args.Page = page

	// Get inventory
	ir, err := proposalInv(&c)
	if err != nil {
		return nil, fmt.Errorf("cmdProposalInv: %v", err)
	}

	// Unpack reply
	s := rcv1.RecordStatuses[status]
	var tokens []string
	switch state {
	case rcv1.RecordStateUnvetted:
		tokens = ir.Unvetted[s]
	case rcv1.RecordStateVetted:
		tokens = ir.Vetted[s]
	}

	return tokens, nil
}

// invUnvetted returns a page of tokens for an unvetted record status.
//
// This function returns with the admin logged out.
func invUnvetted(admin user, status rcv1.RecordStatusT, page uint32) ([]string, error) {
	// Login admin
	err := userLogin(admin)
	if err != nil {
		return nil, err
	}

	// Get a page of tokens
	tokens, err := inv(rcv1.RecordStateUnvetted, status, page)
	if err != nil {
		return nil, err
	}

	// Logout admin
	err = userLogout()
	if err != nil {
		return nil, err
	}

	return tokens, nil
}

// commentNew submits a new comment to a public record.
//
// This function returns with the user logged out.
func commentNew(u user, token, comment string, parentID uint32) error {
	// Login user
	err := userLogin(u)
	if err != nil {
		return err
	}

	// Submit comment
	c := cmdCommentNew{}
	c.Args.Token = token
	c.Args.Comment = comment
	c.Args.ParentID = parentID
	err = c.Execute(nil)
	if err != nil {
		return fmt.Errorf("cmdCommentNew: %v", err)
	}

	// Logout user
	err = userLogout()
	if err != nil {
		return err
	}

	return nil
}

// commentCountForRecord returns the number of comments that have been made on
// a record.
func commentCountForRecord(token string) (uint32, error) {
	c := cmdCommentCount{}
	c.Args.Tokens = []string{token}
	counts, err := commentCount(&c)
	if err != nil {
		return 0, fmt.Errorf("cmdCommentCount: %v", err)
	}
	count, ok := counts[token]
	if !ok {
		return 0, fmt.Errorf("cmdCommentCount: record not found %v", token)
	}
	return count, nil
}

// commentVoteCasts a comment upvote/downvote.
//
// This function returns with the user logged out.
func commentVote(u user, token string, commentID uint32, vote string) error {
	// Login user
	err := userLogin(u)
	if err != nil {
		return err
	}

	c := cmdCommentVote{}
	c.Args.Token = token
	c.Args.CommentID = commentID
	c.Args.Vote = vote
	err = c.Execute(nil)
	if err != nil {
		return err
	}

	// Logout user
	err = userLogout()
	if err != nil {
		return err
	}

	return nil
}
