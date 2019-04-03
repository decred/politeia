// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cockroachdb

import (
	"strconv"
	"time"

	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	database "github.com/decred/politeia/politeiawww/cmsdatabase"
)

// EncodeInvoice encodes a generic database.Invoice instance into a cockroachdb
// Invoice.
func EncodeInvoice(dbInvoice *database.Invoice) *Invoice {
	invoice := Invoice{}

	invoice.Token = dbInvoice.Token
	invoice.UserID = dbInvoice.UserID
	invoice.Month = dbInvoice.Month
	invoice.Year = dbInvoice.Year
	invoice.Status = uint(dbInvoice.Status)
	invoice.StatusChangeReason = dbInvoice.StatusChangeReason
	invoice.Timestamp = time.Unix(dbInvoice.Timestamp, 0)

	files := make([]www.File, len(dbInvoice.Files))
	for i := 0; i < len(dbInvoice.Files); i++ {
		file := www.File{
			Payload: dbInvoice.Files[i].Payload,
			MIME:    dbInvoice.Files[i].MIME,
			Digest:  dbInvoice.Files[i].Digest,
		}
		files[i] = file
	}
	invoice.PublicKey = dbInvoice.PublicKey
	invoice.UserSignature = dbInvoice.UserSignature
	invoice.ServerSignature = dbInvoice.ServerSignature
	invoice.Version = dbInvoice.Version
	invoice.ContractorName = dbInvoice.ContractorName
	invoice.ContractorLocation = dbInvoice.ContractorLocation
	invoice.PaymentAddress = dbInvoice.PaymentAddress
	invoice.ContractorContact = dbInvoice.ContractorContact
	invoice.ContractorRate = dbInvoice.ContractorRate

	for i, dbInvoiceLineItem := range dbInvoice.LineItems {
		invoiceLineItem := EncodeInvoiceLineItem(&dbInvoiceLineItem)
		invoiceLineItem.LineItemKey = dbInvoiceLineItem.InvoiceToken + strconv.Itoa(i)
		invoice.LineItems = append(invoice.LineItems, invoiceLineItem)
	}

	for _, dbInvoiceChange := range dbInvoice.Changes {
		invoiceChange := encodeInvoiceChange(&dbInvoiceChange)
		invoice.Changes = append(invoice.Changes, invoiceChange)
	}
	return &invoice
}

// DecodeInvoice decodes a cockroachdb Invoice instance into a generic database.Invoice.
func DecodeInvoice(invoice *Invoice) (*database.Invoice, error) {
	dbInvoice := database.Invoice{}

	dbInvoice.Token = invoice.Token
	dbInvoice.UserID = invoice.UserID
	dbInvoice.Username = invoice.Username
	dbInvoice.Month = invoice.Month
	dbInvoice.Year = invoice.Year
	dbInvoice.Status = cms.InvoiceStatusT(invoice.Status)
	dbInvoice.StatusChangeReason = invoice.StatusChangeReason
	dbInvoice.Timestamp = invoice.Timestamp.Unix()
	dbInvoice.PublicKey = invoice.PublicKey
	dbInvoice.UserSignature = invoice.UserSignature
	dbInvoice.ServerSignature = invoice.ServerSignature
	dbInvoice.Version = invoice.Version
	dbInvoice.ContractorName = invoice.ContractorName
	dbInvoice.ContractorLocation = invoice.ContractorLocation
	dbInvoice.PaymentAddress = invoice.PaymentAddress
	dbInvoice.ContractorContact = invoice.ContractorContact
	dbInvoice.ContractorRate = invoice.ContractorRate

	for _, invoiceLineItem := range invoice.LineItems {
		dbInvoiceLineItem := DecodeInvoiceLineItem(&invoiceLineItem)
		dbInvoice.LineItems = append(dbInvoice.LineItems, *dbInvoiceLineItem)
	}

	for _, invoiceChange := range invoice.Changes {
		dbInvoiceChanges := decodeInvoiceChange(&invoiceChange)
		dbInvoice.Changes = append(dbInvoice.Changes, *dbInvoiceChanges)
	}
	return &dbInvoice, nil
}

// EncodeInvoiceLineItem encodes a database.LineItem into a cockroachdb line item.
func EncodeInvoiceLineItem(dbLineItem *database.LineItem) LineItem {
	lineItem := LineItem{}
	lineItem.InvoiceToken = dbLineItem.InvoiceToken
	lineItem.Type = uint(dbLineItem.Type)
	lineItem.Subtype = dbLineItem.Subtype
	lineItem.Description = dbLineItem.Description
	lineItem.ProposalURL = dbLineItem.ProposalURL
	lineItem.Labor = dbLineItem.Labor
	lineItem.Expenses = dbLineItem.Expenses
	return lineItem
}

// DecodeInvoiceLineItem decodes a cockroachdb line item into a generic database.LineItem
func DecodeInvoiceLineItem(lineItem *LineItem) *database.LineItem {
	dbLineItem := &database.LineItem{}
	dbLineItem.InvoiceToken = lineItem.InvoiceToken
	dbLineItem.Type = cms.LineItemTypeT(lineItem.Type)
	dbLineItem.Subtype = lineItem.Subtype
	dbLineItem.Description = lineItem.Description
	dbLineItem.ProposalURL = lineItem.ProposalURL
	dbLineItem.Labor = lineItem.Labor
	dbLineItem.Expenses = lineItem.Expenses

	return dbLineItem
}

func encodeInvoiceChange(dbInvoiceChange *database.InvoiceChange) InvoiceChange {
	invoiceChange := InvoiceChange{}
	invoiceChange.AdminPublicKey = dbInvoiceChange.AdminPublicKey
	invoiceChange.NewStatus = uint(dbInvoiceChange.NewStatus)
	invoiceChange.Reason = dbInvoiceChange.Reason
	invoiceChange.Timestamp = time.Unix(dbInvoiceChange.Timestamp, 0)
	return invoiceChange
}

func decodeInvoiceChange(invoiceChange *InvoiceChange) *database.InvoiceChange {
	dbInvoiceChange := &database.InvoiceChange{}
	dbInvoiceChange.AdminPublicKey = invoiceChange.AdminPublicKey
	dbInvoiceChange.NewStatus = cms.InvoiceStatusT(invoiceChange.NewStatus)
	dbInvoiceChange.Reason = invoiceChange.Reason
	dbInvoiceChange.Timestamp = invoiceChange.Timestamp.Unix()
	return dbInvoiceChange
}

// DecodeInvoices decodes an array of cockroachdb Invoice instances into
// generic database.Invoices.
func DecodeInvoices(invoices []Invoice) ([]database.Invoice, error) {
	dbInvoices := make([]database.Invoice, 0, len(invoices))

	for _, invoice := range invoices {
		dbInvoice, err := DecodeInvoice(&invoice)
		if err != nil {
			return nil, err
		}

		dbInvoices = append(dbInvoices, *dbInvoice)
	}

	return dbInvoices, nil
}
