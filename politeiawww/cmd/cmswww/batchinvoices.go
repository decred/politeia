// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	v1 "github.com/decred/politeia/politeiawww/api/cms/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// BatchInvoicesCmd retrieves a set of invoices.
type BatchInvoicesCmd struct{}

// Execute executes the batch invoices command.
func (cmd *BatchInvoicesCmd) Execute(args []string) error {
	// Get server's public key
	vr, err := client.Version()
	if err != nil {
		return err
	}

	// Make batch invoices call
	bir, err := client.BatchInvoices(&v1.BatchInvoices{
		Tokens: args,
	})
	if err != nil {
		return err
	}

	// Verify invoice censorship records from reply
	for _, i := range bir.Invoices {
		err = verifyInvoice(i, vr.PubKey)
		if err != nil {
			return fmt.Errorf("unable to verify invoice %v: %v",
				i.CensorshipRecord.Token, err)
		}
	}

	return shared.PrintJSON(bir)
}

// batchInvoicesHelpMsg is the output of the help command when 'batchinvoices' is specified.
const batchInvoicesHelpMsg = `batchinvoices

Fetch a list of invoices.

Arguments: Tokens

Example (Admin/User):
batchinvoices token1 token2 token3 ...

Result:
{
  "invoices": [
	{
	"status": 						(int) Current status of invoice
	"timestamp": 					(int64) Last update of invoice
	"userid": 						(string) UUID of invoice author
	"username": 					(string) Username of invoice author
	"publickey": 					(string) Author's public key, used to verify signature
	"signature":					(string) Signature of file digest
	"file": 						(File) Invoice csv file
	"version":						(string) Record version
	"input": {
		"version":					(uint) Version of the invoice input
		"month":					(uint) Month of invoice
		"year":						(uint) Year of invoice
		"exchangerate":				(uint) Exchange rate of a given month/year in USD cents
		"contractorname":			(string) Real name of the contractor
		"contractorlocation":		(string) Real location of the contractor
		"contractorcontact":		(string) Contact of the contractor
		"contractorrate":			(uint) Contractor pay rate in USD cents
		"paymentaddress":			(string) Decred payment address
		"lineitems": [
		{
			"type":					(int) Type of work performed
			"domain":				(string) Domain of work performed
			"subdomain":			(string) Subdomain of work performed
			"description":			(string) Description of work performed
			"proposaltoken":		(string) Proposal token that work is associated with
			"subuserid":			(string) User ID of the associated subcontractor
			"subrate":				(uint) Payrate of the subcontractor
			"labor":				(uint) Number of minutes (if type is labor)
			"expenses":				(uint) Total cost in USD cents (if type is expense or misc)
		}
		]
	},
	"payment": {
		"token": 					(string) Payment token
		"address":					(string) Payment address
		"txids":					([]string) TxIds associated with this invoice payment
		"timestarted":				(int64) Time when payment started
		"timelastupdated":			(int64) Time when invoice was last updated
		"amountneeded":				(int64) Amount of decreds needed for payment
		"amountreceived":			(int64) Amount of decreds received from payment
		"status":					(int) Payment status code
	},
	"censorshiprecord": {
		"token":					(string) Invoice censorship token
		"merkle":					(string) Merkle root of invoice
		"signature":				(string) Server-side signature
	}
	}
  ]
}
`
