// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	v1 "github.com/thi4go/politeia/politeiawww/api/cms/v1"
	"github.com/thi4go/politeia/politeiawww/cmd/shared"
)

// ProposalOwnerCmd retreives a list of users that have been filtered using the
// specified filtering params.
type ProposalOwnerCmd struct {
	Args struct {
		Token string `positional-arg-name:"token"`
	} `positional-args:"true" optional:"true"`
}

// Execute executes the cmsusers command.
func (cmd *ProposalOwnerCmd) Execute(args []string) error {
	token := cmd.Args.Token
	if token == "" {
		return fmt.Errorf("token is required")
	}
	u := v1.ProposalOwner{
		ProposalToken: cmd.Args.Token,
	}

	ur, err := client.ProposalOwner(&u)
	if err != nil {
		return err
	}
	return shared.PrintJSON(ur)
}
