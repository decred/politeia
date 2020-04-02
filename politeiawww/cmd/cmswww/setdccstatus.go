// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	cms "github.com/thi4go/politeia/politeiawww/api/cms/v1"
	"github.com/thi4go/politeia/politeiawww/cmd/shared"
)

type SetDCCStatusCmd struct {
	Args struct {
		Token  string `positional-arg-name:"token"`
		Status string `positional-arg-name:"status"`
		Reason string `positional-arg-name:"reason"`
	} `positional-args:"true" optional:"true"`
}

func (cmd *SetDCCStatusCmd) Execute(args []string) error {
	DCCStatus := map[string]cms.DCCStatusT{
		"rejected": cms.DCCStatusRejected,
		"approved": cms.DCCStatusApproved,
	}
	// Check for user identity
	if cfg.Identity == nil {
		return shared.ErrUserIdentityNotFound
	}

	status, ok := DCCStatus[strings.ToLower(cmd.Args.Status)]
	if !ok {
		return fmt.Errorf("Invalid status: '%v'.  "+
			"Valid statuses are:\n"+
			"  rejected  reject the DCC\n"+
			"  approved  approve the DCC",
			cmd.Args.Status)
	}

	sig := cfg.Identity.SignMessage([]byte(cmd.Args.Token +
		strconv.Itoa(int(status)) + cmd.Args.Reason))
	sd := &cms.SetDCCStatus{
		Token:     cmd.Args.Token,
		Status:    status,
		Reason:    cmd.Args.Reason,
		PublicKey: hex.EncodeToString(cfg.Identity.Public.Key[:]),
		Signature: hex.EncodeToString(sig[:]),
	}

	// Print request details
	err := shared.PrintJSON(sd)
	if err != nil {
		return err
	}

	// Send request
	sisr, err := client.SetDCCStatus(sd)
	if err != nil {
		return err
	}

	return shared.PrintJSON(sisr)
}
