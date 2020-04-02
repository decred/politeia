// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/thi4go/politeia/politeiawww/cmd/shared"
)

// DCCDetailsCmd retrieves the details of a dcc.
type DCCDetailsCmd struct {
	Args struct {
		Token string `positional-arg-name:"token" required:"true"` // Censorship token
	} `positional-args:"true"`
}

// Execute executes the dcc details command.
func (cmd *DCCDetailsCmd) Execute(args []string) error {
	// Get server's public key
	vr, err := client.Version()
	if err != nil {
		return err
	}

	// Get dcc
	ddr, err := client.DCCDetails(cmd.Args.Token)
	if err != nil {
		return err
	}

	// Verify dcc censorship record
	err = verifyDCC(ddr.DCC, vr.PubKey)
	if err != nil {
		return fmt.Errorf("unable to verify dcc %v: %v",
			ddr.DCC.CensorshipRecord.Token, err)
	}

	// Print invoice details
	return shared.PrintJSON(ddr)
}
