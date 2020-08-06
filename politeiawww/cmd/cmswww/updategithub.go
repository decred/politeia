// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	v1 "github.com/decred/politeia/politeiawww/api/cms/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// UpdateCodeStatsCmd
type UpdateCodeStatsCmd struct {
	Args struct {
		Organization string `positional-arg-name:"organization"`
	} `positional-args:"true" optional:"true"`
	Repository string `long:"repo" optional:"true" description:"Optional repository argument to only update a singular repo"`
	Month      int    `long:"month" optional:"true" description:"Optional argument to update codestats for a given month"`
	Year       int    `long:"year" optional:"true" description:"Optional argument to update codestats for a given year"`
}

func (cmd *UpdateCodeStatsCmd) Execute(args []string) error {
	org := cmd.Args.Organization

	if org == "" {
		return fmt.Errorf("you must specify an organization.")
	}

	pir, err := client.UpdateCodeStats(
		&v1.UpdateCodeStats{
			Organization: cmd.Args.Organization,
			Repository:   cmd.Repository,
			Month:        cmd.Month,
			Year:         cmd.Year,
		})
	if err != nil {
		return err
	}

	return shared.PrintJSON(pir)
}
