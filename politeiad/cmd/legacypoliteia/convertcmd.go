// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/decred/politeia/util"
	"github.com/google/uuid"
)

const (
	// Default command settings
	defaultLegacyDir = "./legacy-politeia-data"
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

	// Clean legacy directory path
	*legacyDir = util.CleanAndExpandPath(*legacyDir)

	// Verify user ID
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

	// Setup cmd context
	cmd := convertCmd{
		gitRepo:      gitRepo,
		legacyDir:    *legacyDir,
		skipComments: *skipComments,
		skipBallots:  *skipBallots,
		ballotLimit:  *ballotLimit,
		userID:       *userID,
	}

	// Convert the git proposals
	return cmd.convertGitProposals()
}

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
		fmt.Printf("Converting %v (%v/%v)\n", token, count, len(tokens))

		// Setup proposal
		p := proposal{
			RecordMetadata:   backend.RecordMetadata{},
			Files:            nil,
			Metadata:         nil,
			ProposalMetadata: pi.ProposalMetadata{},
			StatusChanges:    nil,
			VoteMetadata:     ticketvote.VoteMetadata{},
			AuthDetails:      ticketvote.AuthDetails{},
			VoteDetails:      ticketvote.VoteDetails{},
			CommentAdds:      nil,
			CommentDels:      nil,
			CommentVotes:     nil,
		}

		// Save proposal
		err = saveProposal(c.legacyDir, &p)
		if err != nil {
			return err
		}

		count++
	}

	return nil
}

// decodeVersion returns the version field from the provided JSON payload. This
// function should only be used when the payload contains a single struct with
// a "version" field.
func decodeVersion(payload []byte) (uint, error) {
	data := make(map[string]interface{}, 32)
	err := json.Unmarshal(payload, &data)
	if err != nil {
		return 0, err
	}
	version := uint(data["version"].(float64))
	if version == 0 {
		return 0, fmt.Errorf("version not found")
	}
	return version, nil
}
