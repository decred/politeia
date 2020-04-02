// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	v1 "github.com/thi4go/politeia/politeiawww/api/cms/v1"
	"github.com/thi4go/politeia/politeiawww/cmd/shared"
)

// GetDCCsCmd gets all dccs by status.
type GetDCCsCmd struct {
	Args struct {
		Status int `long:"status"`
	}
}

// Execute executes the get dccs command.
func (cmd *GetDCCsCmd) Execute(args []string) error {
	// Get server public key
	vr, err := client.Version()
	if err != nil {
		return err
	}

	gdr, err := client.GetDCCs(
		&v1.GetDCCs{
			Status: v1.DCCStatusT(cmd.Args.Status),
		})
	if err != nil {
		return err
	}

	// Verify dcc censorship records
	for _, p := range gdr.DCCs {
		err := verifyDCC(p, vr.PubKey)
		if err != nil {
			return fmt.Errorf("unable to verify dcc %v: %v",
				p.CensorshipRecord.Token, err)
		}
	}

	// Print user invoices
	return shared.PrintJSON(gdr)
}
