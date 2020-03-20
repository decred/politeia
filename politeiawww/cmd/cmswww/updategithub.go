// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	v1 "github.com/decred/politeia/politeiawww/api/cms/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// UpdateGithubCmd
type UpdateGithubCmd struct {
	Args struct {
		Organization string `positional-arg-name:"organization"`
	} `positional-args:"true" optional:"true"`
	Repository    string `long:"repo" optional:"true" description:"Optional repository argument to only update a singular repo"`
	OnlyCodeStats bool   `long:"onlycodestats" optional:"true" description:"Optional flag to only update codestats and not query github api"`
}

func (cmd *UpdateGithubCmd) Execute(args []string) error {
	org := cmd.Args.Organization

	if org == "" {
		return fmt.Errorf("you must specify an organization.")
	}

	pir, err := client.UpdateGithub(
		&v1.UpdateGithub{
			Organization:  cmd.Args.Organization,
			Repository:    cmd.Repository,
			OnlyCodeStats: cmd.OnlyCodeStats,
		})
	if err != nil {
		return err
	}

	return shared.PrintJSON(pir)
}
