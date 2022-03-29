// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"

	"path/filepath"

	"github.com/decred/politeia/politeiad/cmd/legacypoliteia/gitbe"
)

// git_filepath.go contains the code that parses information from the legacy
// git repo file paths and that determines the file paths of the various pieces
// of proposal data.

// parseProposalTokens recursively walks the provided directory and returns an
// inventory of all legacy proposal tokens that are parsed from the git repo
// file paths. The tokens are returned in alphabetical order.
func parseProposalTokens(dirPath string) ([]string, error) {
	tokens := make(map[string]struct{}, 256)
	err := filepath.WalkDir(dirPath,
		func(path string, d fs.DirEntry, err error) error {
			// We only care about directories
			if !d.IsDir() {
				return nil
			}

			// Parse the token from the path
			token, ok := parseProposalToken(path)
			if ok {
				tokens[token] = struct{}{}
				return nil
			}

			return nil
		})
	if err != nil {
		return nil, err
	}

	// Put the tokens into a slice and sort them alphabetically
	sorted := make([]string, 0, len(tokens))
	for token := range tokens {
		sorted = append(sorted, token)
	}
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i] < sorted[j]
	})

	return sorted, nil
}

var (
	// Regular expression that matches the git proposal token from a proposal
	// parent directory.
	expLegacyProposalToken   = `[0-9a-f]{64}`
	regexLegacyProposalToken = regexp.MustCompile(expLegacyProposalToken)
)

// parseProposalToken parses and returns the legacy proposal token from a
// git repo path.
//
// Input:
// "fdd68c87961549750adf29e178128210cb310294080211cf6a35792aa1bb7f63.json"
// Output:
// "fdd68c87961549750adf29e178128210cb310294080211cf6a35792aa1bb7f63", true
//
// Input:
// "mainnet/fdd68c87961549750adf29e178128210cb310294080211cf6a35792aa1bb7f63/1"
// Output:
// "fdd68c87961549750adf29e178128210cb310294080211cf6a35792aa1bb7f63", true
func parseProposalToken(path string) (string, bool) {
	var (
		token = regexLegacyProposalToken.FindString(path)
		ok    = (token != "")
	)
	return token, ok
}

// praseLatestProposalVersion parses latest version of a legacy proposal from
// the git file path and returns it.
//
// Example path: [gitRepo]/[token]/[version]/
func parseLatestProposalVersion(gitRepo, token string) (uint64, error) {
	// Compile a list of all directories. The version numbers
	// are the directory name.
	dirs := make(map[string]struct{}, 64)
	err := filepath.WalkDir(filepath.Join(gitRepo, token),
		func(path string, d fs.DirEntry, err error) error {
			if !d.IsDir() {
				return nil
			}
			dirs[d.Name()] = struct{}{}
			return nil
		})
	if err != nil {
		return 0, err
	}

	// Parse the version number from the directory name
	versions := make(map[uint64]struct{}, 64)
	for dirname := range dirs {
		u, err := strconv.ParseUint(dirname, 10, 32)
		if err != nil {
			// Not a version directory
			continue
		}
		versions[u] = struct{}{}
	}
	if err != nil {
		return 0, err
	}

	// Find the most recent version
	var latest uint64
	for version := range versions {
		if version > latest {
			latest = version
		}
	}
	if latest == 0 {
		return 0, fmt.Errorf("latest version not found for %v", token)
	}

	return latest, nil
}

var (
	// Regular expersion that matches the token and version number from a
	// proposal directory path.
	expProposalVersion   = `[0-9a-f]{64}\/[0-9]{1,}`
	regexProposalVersion = regexp.MustCompile(expProposalVersion)
)

// proposalVersion parses the version number for the proposal directory path
// and returns it.
func parseProposalVersion(proposalDir string) (uint32, error) {
	var (
		subPath    = regexProposalVersion.FindString(proposalDir)
		versionStr = filepath.Base(subPath)
	)
	u, err := strconv.ParseUint(versionStr, 10, 32)
	if err != nil {
		return 0, err
	}

	return uint32(u), nil
}

// parseProposalAttachmentFiles parses the filenames of all proposal attachment
// files and returns them. This function does NOT return the file path, just
// the file name. The proposal index file and proposal metadata file are not
// considered to be attachments.
func parseProposalAttachmentFilenames(proposalDir string) ([]string, error) {
	var (
		notAnAttachmentFile = map[string]struct{}{
			gitbe.IndexFilename:            {},
			gitbe.ProposalMetadataFilename: {},
		}

		payloadDir = payloadDirPath(proposalDir)
		filenames  = make([]string, 0, 64)
	)

	// Walk the payload directory
	err := filepath.WalkDir(payloadDir,
		func(path string, d fs.DirEntry, err error) error {
			// There shouldn't be any nested directories
			// in the payload directory, but check just
			// in case.
			if d.IsDir() {
				return nil
			}

			if _, ok := notAnAttachmentFile[d.Name()]; ok {
				// Not an attachment; skip
				return nil
			}

			// This is an attachment file
			filenames = append(filenames, d.Name())

			return nil
		})
	if err != nil {
		return nil, err
	}

	return filenames, nil
}

func recordMetadataPath(proposalDir string) string {
	return filepath.Join(proposalDir, gitbe.RecordMetadataFilename)
}

func payloadDirPath(proposalDir string) string {
	return filepath.Join(proposalDir, gitbe.RecordPayloadPath)
}

func indexFilePath(proposalDir string) string {
	return filepath.Join(payloadDirPath(proposalDir), gitbe.IndexFilename)
}

func attachmentFilePath(proposalDir, attachmentFilename string) string {
	return filepath.Join(payloadDirPath(proposalDir), attachmentFilename)
}

func proposalMetadataPath(proposalDir string) string {
	return filepath.Join(payloadDirPath(proposalDir),
		gitbe.ProposalMetadataFilename)
}

func proposalGeneralPath(proposalDir string) string {
	return filepath.Join(proposalDir, gitbe.MDStreamProposalGeneral)
}

func statusChangesPath(proposalDir string) string {
	return filepath.Join(proposalDir, gitbe.MDStreamStatusChanges)
}

func commentsJournalPath(proposalDir string) string {
	return filepath.Join(decredPluginPath(proposalDir),
		gitbe.CommentsJournalFilename)
}

func authorizeVotePath(proposalDir string) string {
	return filepath.Join(proposalDir, gitbe.MDStreamAuthorizeVote)
}

func startVotePath(proposalDir string) string {
	return filepath.Join(proposalDir, gitbe.MDStreamStartVote)
}

func startVoteReplyPath(proposalDir string) string {
	return filepath.Join(proposalDir, gitbe.MDStreamStartVoteReply)
}

func decredPluginPath(proposalDir string) string {
	return filepath.Join(proposalDir, gitbe.DecredPluginPath)
}

func ballotsJournalPath(proposalDir string) string {
	return filepath.Join(decredPluginPath(proposalDir),
		gitbe.BallotJournalFilename)
}
