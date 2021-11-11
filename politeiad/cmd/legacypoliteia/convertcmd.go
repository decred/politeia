// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/decred/politeia/util"
	"github.com/google/uuid"
)

/*
TODO
-[ ] Handle standard proposal
-[ ] Handle dup cast votes and comments
-[ ] Pull user IDs from prod by pubkey and hardcode
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
	legacyDir    = convertFlags.String("legacydir", defaultLegacyDir, "")
	skipComments = convertFlags.Bool("skipcomments", false, "")
	skipBallots  = convertFlags.Bool("skipballots", false, "")
	ballotLimit  = convertFlags.Int("ballotlimit", 0, "")
	userID       = convertFlags.String("userid", "", "")
)

type convertCmd struct {
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
	// Parse the CLI flags
	err := convertFlags.Parse(args)
	if err != nil {
		return err
	}

	// Verify the git repo exists
	if len(args) == 0 {
		return fmt.Errorf("missing git repo argument")
	}
	gitRepo := util.CleanAndExpandPath(args[0])
	if _, err := os.Stat(gitRepo); err != nil {
		return fmt.Errorf("git repo not found: %v", gitRepo)
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

	// Setup the cmd context
	c := convertCmd{
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
		// https://proposals-archive.decred.org/proposals/95a1409
		"95a14094485c92ed3f578b650bd76c5f8c3fd6392650c16bd4ae37e6167c040d": {},

		// https://proposals-archive.decred.org/proposals/0230918
		"023091831f6434f743f3a317aacf8c73a123b30d758db854a2f294c0b3341bcc": {},
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

		// Save the proposal to disk
		err = saveProposal(c.legacyDir, &p)
		if err != nil {
			return err
		}

		count++
	}

	return nil
}
