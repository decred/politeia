// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
)

type SetInvoiceStatusCmd struct {
	Args struct {
		Token  string `positional-arg-name:"token"`
		Status string `positional-arg-name:"status"`
		Reason string `positional-arg-name:"reason"`
	} `positional-args:"true" optional:"true"`
}

func (cmd *SetInvoiceStatusCmd) Execute(args []string) error {
	InvoiceStatus := map[string]cms.InvoiceStatusT{
		"updated":  cms.InvoiceStatusUpdated,
		"rejected": cms.InvoiceStatusRejected,
		"approved": cms.InvoiceStatusApproved,
		"paid":     cms.InvoiceStatusPaid,
	}
	// Check for user identity
	if cfg.Identity == nil {
		return errUserIdentityNotFound
	}

	status, ok := InvoiceStatus[strings.ToLower(cmd.Args.Status)]
	if !ok {
		return fmt.Errorf("Invalid status: %v", cmd.Args.Status)
	}

	// Setup request
	sig := cfg.Identity.SignMessage([]byte(cmd.Args.Token +
		strconv.Itoa(int(status)) + cmd.Args.Reason))

	sis := &cms.SetInvoiceStatus{
		Token:     cmd.Args.Token,
		Status:    status,
		Reason:    cmd.Args.Reason,
		PublicKey: hex.EncodeToString(cfg.Identity.Public.Key[:]),
		Signature: hex.EncodeToString(sig[:]),
	}

	// Print request details
	err := printJSON(sis)
	if err != nil {
		return err
	}

	// Send request
	sisr, err := client.SetInvoiceStatus(sis)
	if err != nil {
		return err
	}

	return printJSON(sisr)
}
