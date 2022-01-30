// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/util"
	"github.com/google/uuid"
)

/*
TODO
-[ ] Handle standard proposal
-[ ] Handle dup cast votes and comments
-[ ] Handle RFPs
*/

const (
	// Default command settings
	defaultLegacyDir = "./legacy-politeia-data"

	// filePermissions is the file permissions that are used for all directory
	// and file creation in this tool.
	filePermissions = 0755
)

var (
	// CLI flags for the convert command
	convertFlags = flag.NewFlagSet(convertCmdName, flag.ContinueOnError)
	legacyDir    = convertFlags.String("legacydir", defaultLegacyDir,
		"default legacy data dir")
	skipComments = convertFlags.Bool("skipcomments", false, "skip comments")
	skipBallots  = convertFlags.Bool("skipballots", false, "skip ballots")
	ballotLimit  = convertFlags.Int("ballotlimit", 0, "limit parsed votes")
	userID       = convertFlags.String("userid", "", "replace user IDs")
)

type convertCmd struct {
	client       *http.Client
	gitRepo      string
	legacyDir    string
	skipComments bool
	skipBallots  bool
	ballotLimit  int
	userID       string
}

// execConvertComd executes the convert command.
//
// The convert command parses a legacy git repo, converts the data into types
// supported by the tstore backend, then writes the converted JSON data to
// disk. This data can be imported into tstore using the 'import' command.
func execConvertCmd(args []string) error {
	// Verify the git repo exists
	if len(args) == 0 {
		return fmt.Errorf("missing git repo argument")
	}
	gitRepo := util.CleanAndExpandPath(args[0])
	if _, err := os.Stat(gitRepo); err != nil {
		return fmt.Errorf("git repo not found: %v", gitRepo)
	}

	// Parse the CLI flags
	err := convertFlags.Parse(args[1:])
	if err != nil {
		return err
	}

	// Clean the legacy directory path
	*legacyDir = util.CleanAndExpandPath(*legacyDir)

	// Verify the user ID
	if *userID != "" {
		_, err = uuid.Parse(*userID)
		if err != nil {
			return fmt.Errorf("invalid user id '%v': %v", *userID, err)
		}
	}

	// Setup the legacy directory
	err = os.MkdirAll(*legacyDir, filePermissions)
	if err != nil {
		return err
	}

	client, err := util.NewHTTPClient(false, "")
	if err != nil {
		return err
	}

	// Setup the cmd context
	c := convertCmd{
		client:       client,
		gitRepo:      gitRepo,
		legacyDir:    *legacyDir,
		skipComments: *skipComments,
		skipBallots:  *skipBallots,
		ballotLimit:  *ballotLimit,
		userID:       *userID,
	}

	// Convert the git proposals
	return c.convertGitProposals()
}

var (
	// TODO Remove this. It's hardcoded in for now to help with testing.
	doNotSkip = map[string]struct{}{
		// Proposal with image attachments. Standard vote that was approved.
		//
		// https://proposals-archive.decred.org/proposals/0230918
		"023091831f6434f743f3a317aacf8c73a123b30d758db854a2f294c0b3341bcc": {},

		// Abandoned proposal
		//
		// https://proposals-archive.decred.org/proposals/8a09324
		"8a0932475eba2139df82f885fbdff9845e98551b47c44c378bf51840ae616334": {},

		// RFP parent proposal
		//
		// https://proposals-archive.decred.org/proposals/91becea
		"91beceac460d9b790a01fb2e537320820bab66babfeb5eb49a022ea5952b5d73": {},
	}
)

// convertGitProposals converts the git proposals to tstore proposals, saving
// the tstore proposals to disk as the conversion is finished.
func (c *convertCmd) convertGitProposals() error {
	// Build an inventory of all git proposal tokens
	tokens, err := gitProposalTokens(c.gitRepo)
	if err != nil {
		return err
	}

	fmt.Printf("Found %v legacy git proposals\n", len(tokens))

	// Convert the data for each proposal into tstore supported types.
	count := 1
	for token := range tokens {
		// TODO Remove this. It's hardcoded in for now to help with testing.
		if _, ok := doNotSkip[token]; !ok {
			continue
		}

		fmt.Printf("Converting proposal (%v/%v)\n", count, len(tokens))

		// Get the path to the most recent version of the proposal.
		// The version number is the directory name. We only import
		// the most recent version of the proposal.
		//
		// Example path: [gitRepo]/[token]/[version]/
		v, err := latestVersion(c.gitRepo, token)
		if err != nil {
			return err
		}

		version := strconv.FormatUint(v, 10)
		proposalDir := filepath.Join(c.gitRepo, token, version)

		// Convert git backend types to tstore backend types
		recordMD, err := convertRecordMetadata(proposalDir)
		if err != nil {
			return err
		}
		files, err := convertFiles(proposalDir)
		if err != nil {
			return err
		}
		proposalMD, err := convertProposalMetadata(proposalDir)
		if err != nil {
			return err
		}
		voteMD, err := convertVoteMetadata(proposalDir)
		if err != nil {
			return err
		}
		userMD, err := convertUserMetadata(proposalDir)
		if err != nil {
			return err
		}
		// Populate user ID
		switch {
		case c.userID != "":
			// Replacement user ID is not empty, hardcode it
			userMD.UserID = c.userID

		case c.userID == "":
			// No replacement user ID is given, pull user ID using the
			// present public key.
			u, err := c.fetchUserByPubKey(userMD.PublicKey)
			if err != nil {
				return err
			}
			userMD.UserID = u.ID
		}
		statusChanges, err := convertStatusChanges(proposalDir)
		if err != nil {
			return err
		}
		authDetails, err := convertAuthDetails(proposalDir)
		if err != nil {
			return err
		}
		voteDetails, err := convertVoteDetails(proposalDir)
		if err != nil {
			return err
		}
		castVotes, err := convertCastVotes(proposalDir)
		if err != nil {
			return err
		}
		commentData, err := convertComments(proposalDir)
		if err != nil {
			return err
		}

		// Build the proposal
		p := proposal{
			RecordMetadata:   *recordMD,
			Files:            files,
			ProposalMetadata: *proposalMD,
			VoteMetadata:     voteMD,
			UserMetadata:     *userMD,
			StatusChanges:    statusChanges,
			AuthDetails:      authDetails,
			VoteDetails:      voteDetails,
			CastVotes:        castVotes,
			CommentAdds:      commentData.Adds,
			CommentDels:      commentData.Dels,
			CommentVotes:     commentData.Votes,
		}
		err = sanityChecks(&p)
		if err != nil {
			return err
		}

		// Save the proposal to disk
		err = saveProposal(c.legacyDir, &p)
		if err != nil {
			return err
		}

		count++
	}

	return nil
}

// userReply is politeiawww's reply to the users request.
type usersReply struct {
	TotalUsers   uint64 `json:"totalusers,omitempty"`
	TotalMatches uint64 `json:"totalmatches"`
	Users        []user `json:"users"`
}

// user is returned from the politeiawww API.
type user struct {
	ID       string `json:"id"`
	Email    string `json:"email,omitempty"`
	Username string `json:"username"`
}

// fetchUserByPubKey makes a call to the politeia API requesting the user
// with the provided public key.
func (c *convertCmd) fetchUserByPubKey(pubkey string) (*user, error) {
	url := "https://proposals.decred.org/api/v1/users?publickey=" + pubkey
	r, err := c.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	var ur usersReply
	err = json.Unmarshal(body, &ur)
	if err != nil {
		return nil, err
	}

	if len(ur.Users) == 0 {
		return nil, fmt.Errorf("no user found for pubkey %v", pubkey)
	}

	return &ur.Users[0], nil
}

// sanityChecks performs some basic sanity checks on the proposal data.
func sanityChecks(p *proposal) error {
	switch {
	case len(p.Files) == 0:
		return fmt.Errorf("no files found")
	case p.ProposalMetadata.Name == "":
		return fmt.Errorf("proposal name missing")
	case p.UserMetadata.UserID == "":
		return fmt.Errorf("user id missing")
	}

	// Checks based on record status
	switch p.RecordMetadata.Status {
	case backend.StatusArchived:
		// Archived proposals will have two status
		// changes and no vote data.
		if len(p.StatusChanges) != 2 {
			return fmt.Errorf("invalid status changes")
		}
		if p.AuthDetails != nil {
			return fmt.Errorf("auth details invalid")
		}
		if p.VoteDetails != nil {
			return fmt.Errorf("vote details invalid")
		}
		if len(p.CastVotes) != 0 {
			return fmt.Errorf("cast votes invalid")
		}

	case backend.StatusPublic:
		// All non-archived proposals will be public,
		// with a single status change, and will have
		// the vote data populated.
		if len(p.StatusChanges) != 1 {
			return fmt.Errorf("invalid status changes")
		}
		if p.AuthDetails == nil {
			return fmt.Errorf("auth details missing")
		}
		if p.VoteDetails == nil {
			return fmt.Errorf("vote details missing")
		}
		if len(p.CastVotes) == 0 {
			return fmt.Errorf("cast votes missing")
		}

	default:
		return fmt.Errorf("unknown record status")
	}

	return nil
}
