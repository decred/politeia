// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	v1 "github.com/thi4go/politeia/politeiawww/api/cms/v1"
	"github.com/thi4go/politeia/politeiawww/cmd/shared"
)

// UserSubContractorsCmd gets the subcontractors for the logged in user.
type UserSubContractorsCmd struct {
}

// Execute executes the user subcontractors command.
func (cmd *UserSubContractorsCmd) Execute(args []string) error {
	// Get user subcontractors
	uir, err := client.UserSubContractors(
		&v1.UserSubContractors{})
	if err != nil {
		return err
	}

	// Print user sub contractors
	return shared.PrintJSON(uir)
}
