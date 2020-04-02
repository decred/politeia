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

type SetInvoiceStatusCmd struct {
	Args struct {
		Version string `positional-arg-name:"version"`
		Token   string `positional-arg-name:"token"`
		Status  string `positional-arg-name:"status"`
		Reason  string `positional-arg-name:"reason"`
	} `positional-args:"true" optional:"true"`
}

func (cmd *SetInvoiceStatusCmd) Execute(args []string) error {
	InvoiceStatus := map[string]cms.InvoiceStatusT{
		"rejected": cms.InvoiceStatusRejected,
		"approved": cms.InvoiceStatusApproved,
		"disputed": cms.InvoiceStatusDisputed,
	}
	// Check for user identity
	if cfg.Identity == nil {
		return shared.ErrUserIdentityNotFound
	}

	status, ok := InvoiceStatus[strings.ToLower(cmd.Args.Status)]
	if !ok {
		return fmt.Errorf("Invalid status: %v", cmd.Args.Status)
	}

	// Setup request
	sig := cfg.Identity.SignMessage([]byte(cmd.Args.Token + cmd.Args.Version +
		strconv.Itoa(int(status)) + cmd.Args.Reason))

	sis := &cms.SetInvoiceStatus{
		Token:     cmd.Args.Token,
		Status:    status,
		Reason:    cmd.Args.Reason,
		PublicKey: hex.EncodeToString(cfg.Identity.Public.Key[:]),
		Signature: hex.EncodeToString(sig[:]),
	}

	// Print request details
	err := shared.PrintJSON(sis)
	if err != nil {
		return err
	}

	// Send request
	sisr, err := client.SetInvoiceStatus(sis)
	if err != nil {
		return err
	}

	return shared.PrintJSON(sisr)
}

// setInvoiceStatusHelpMsg is the output of the help command when
// "setinvoicestatus" is specified.
const setInvoiceStatusHelpMsg = `setinvoicestatus "token" "status"

Set the status of a invoice. Requires admin privileges.

Arguments:
1. version    (string, required)   Current version of the invoice record
1. token      (string, required)   Invoice censorship token
2. status     (string, required)   New status (approved, disputed, rejected)
3. message    (string)             Status change message

Request:
{
  "token":           (string)          Censorship token
  "invoicestatus":   (InvoiceStatusT)  Invoice status code    
  "signature":       (string)          Signature of invoice status change
  "publickey":       (string)          Public key of user changing invoice status
}

Response:
{
  "invoice": {
	  "month":         (uint16)       Month of invoice
	  "year":          (uint16)       Year of invoice
	  "state":         (PropStateT)   Current state of invoice
	  "status":        (PropStatusT)  Current status of invoice
	  "timestamp":     (int64)        Timestamp of last update of invoice
	  "userid":        (string)       ID of user who submitted invoice
	  "username":      (string)       Username of user who submitted invoice
	  "publickey":     (string)       Public key used to sign invoice
	  "signature":     (string)       Signature of merkle root
	  "files": [
		{
		  "name":      (string)       Filename 
		  "mime":      (string)       Mime type 
		  "digest":    (string)       File digest 
		  "payload":   (string)       File payload 
		}
	  ],
	  "numcomments":   (uint)    Number of comments on the invoice
	  "version": 		 (string)  Version of invoice
	  "censorshiprecord": {	
		"token":       (string)  Censorship token
		"merkle":      (string)  Merkle root of invoice
		"signature":   (string)  Server side signature of []byte(Merkle+Token)
	  }
	}
}`
