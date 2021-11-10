// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"os"
	"path/filepath"
	"regexp"
)

var (
	// Regular expression that matches the git proposal token from a proposal
	// parent directory.
	expGitProposalToken   = `[0-9a-f]{64}`
	regexGitProposalToken = regexp.MustCompile(expGitProposalToken)
)

// gitProposalToken takes a git repo path and returns the proposal token from
// the path if the path corresponds to the proposal parent directory.
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
func gitProposalToken(path string) (string, bool) {
	var (
		gitToken = regexGitProposalToken.FindString(path)
		ok       = (gitToken != "")
	)
	return gitToken, ok
}

// gitProposalTokens recursively walks the provided directory and returns an
// inventory of all git proposal tokens found in file paths.
func gitProposalTokens(dirPath string) (map[string]interface{}, error) {
	tokens := make(map[string]interface{}, 256)
	err := filepath.Walk(dirPath,
		func(path string, f os.FileInfo, err error) error {
			// We only care about directories
			if !f.IsDir() {
				return nil
			}

			// Get the token from the path
			token, ok := gitProposalToken(path)
			if ok {
				tokens[token] = struct{}{}
				return nil
			}

			return nil
		})
	if err != nil {
		return nil, err
	}
	return tokens, nil
}
