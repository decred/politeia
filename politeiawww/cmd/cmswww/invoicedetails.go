// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/thi4go/politeia/politeiawww/cmd/shared"
)

// InvoiceDetailsCmd retrieves the details of a invoice.
type InvoiceDetailsCmd struct {
	Args struct {
		Token string `positional-arg-name:"token" required:"true"` // Censorship token
	} `positional-args:"true"`
}

// Execute executes the invoice details command.
func (cmd *InvoiceDetailsCmd) Execute(args []string) error {
	// Get server's public key
	vr, err := client.Version()
	if err != nil {
		return err
	}

	// Get invoice
	idr, err := client.InvoiceDetails(cmd.Args.Token)
	if err != nil {
		return err
	}

	// Verify invoice censorship record
	err = verifyInvoice(idr.Invoice, vr.PubKey)
	if err != nil {
		return fmt.Errorf("unable to verify invoice %v: %v",
			idr.Invoice.CensorshipRecord.Token, err)
	}

	// Print invoice details
	return shared.PrintJSON(idr)
}

// invoiceDetailsHelpMsg is the output for the help command when
// 'invoicedetails' is specified.
const invoiceDetailsHelpMsg = `invoicedetails "token"

Get a invoice.

Arguments:
1. token      (string, required)   Censorship token

Result:
{
  "invoice": {
    "name":          (string)  Suggested short invoice name 
    "state":         (PropStateT)  Current state of invoice
    "status":        (PropStatusT)  Current status of invoice
    "timestamp":     (int64)  Timestamp of last update of invoice
    "userid":        (string)  ID of user who submitted invoice
    "username":      (string)  Username of user who submitted invoice
    "publickey":     (string)  Public key used to sign invoice
    "signature":     (string)  Signature of merkle root
    "files": [
      {
        "name":      (string)  Filename 
        "mime":      (string)  Mime type 
        "digest":    (string)  File digest 
        "payload":   (string)  File payload 
      }
    ],
    "numcomments":   (uint)  Number of comments on the invoice
    "version": 		 (string)  Version of invoice
    "censorshiprecord": {	
      "token":       (string)  Censorship token
      "merkle":      (string)  Merkle root of invoice
      "signature":   (string)  Server side signature of []byte(Merkle+Token)
    }
  }
}`
