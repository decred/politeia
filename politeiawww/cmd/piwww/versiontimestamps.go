// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// VersionTimestampsCmd retrieves the timestamps at each each version of a
// proposal was created.
type VersionTimestampsCmd struct {
	Args struct {
		Token string `positional-arg-name:"token" required:"true"` // Censorship token
	} `positional-args:"true"`
}

// Execute executes the version timestamps command
func (cmd *VersionTimestampsCmd) Execute(args []string) error {
	// Get timestamps
	vtsr, err := client.VersionTimestamps(cmd.Args.Token)
	if err != nil {
		return err
	}

	// Print version timestamps reply
	return shared.PrintJSON(vtsr)
}

// versionTimestampsHelpMsg is the output for the help command when
// 'proposaldetails' is specified.
const versionTimestampsHelpMsg = `versiontimestamps "token"

Get the timestamps at which each version of a proposal were created.

Arguments:
1. token      (string, required)   Censorship token

Result:
{
  "timestamps": ([]int64) Timestamps of each version of the proposal
}`
