// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cockroachdb

import (
	"strconv"
	"time"

	cms "github.com/thi4go/politeia/politeiawww/api/cms/v1"
	www "github.com/thi4go/politeia/politeiawww/api/www/v1"
	database "github.com/thi4go/politeia/politeiawww/cmsdatabase"
)

// EncodeInvoice encodes a generic database.Invoice instance into a cockroachdb
// Invoice.
func EncodeInvoice(dbInvoice *database.Invoice) *Invoice {
	invoice := Invoice{}

	invoice.Token = dbInvoice.Token
	invoice.UserID = dbInvoice.UserID
	invoice.Month = dbInvoice.Month
	invoice.Year = dbInvoice.Year
	invoice.ExchangeRate = dbInvoice.ExchangeRate
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
		invoiceLineItem.LineItemKey = dbInvoice.Token + strconv.Itoa(i)
		invoice.LineItems = append(invoice.LineItems, invoiceLineItem)
	}

	for _, dbInvoiceChange := range dbInvoice.Changes {
		invoiceChange := encodeInvoiceChange(&dbInvoiceChange)
		invoice.Changes = append(invoice.Changes, invoiceChange)
	}

	invoice.Payments = encodePayments(&dbInvoice.Payments)
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
	dbInvoice.ExchangeRate = invoice.ExchangeRate
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

	dbInvoice.Payments = decodePayment(&invoice.Payments)
	return &dbInvoice, nil
}

// EncodeInvoiceLineItem encodes a database.LineItem into a cockroachdb line item.
func EncodeInvoiceLineItem(dbLineItem *database.LineItem) LineItem {
	lineItem := LineItem{}
	lineItem.InvoiceToken = dbLineItem.InvoiceToken
	lineItem.Type = uint(dbLineItem.Type)
	lineItem.Domain = dbLineItem.Domain
	lineItem.Subdomain = dbLineItem.Subdomain
	lineItem.Description = dbLineItem.Description
	lineItem.ProposalURL = dbLineItem.ProposalURL
	lineItem.Labor = dbLineItem.Labor
	lineItem.Expenses = dbLineItem.Expenses
	lineItem.ContractorRate = dbLineItem.ContractorRate
	return lineItem
}

// DecodeInvoiceLineItem decodes a cockroachdb line item into a generic database.LineItem
func DecodeInvoiceLineItem(lineItem *LineItem) *database.LineItem {
	dbLineItem := &database.LineItem{}
	dbLineItem.InvoiceToken = lineItem.InvoiceToken
	dbLineItem.Type = cms.LineItemTypeT(lineItem.Type)
	dbLineItem.Domain = lineItem.Domain
	dbLineItem.Subdomain = lineItem.Subdomain
	dbLineItem.Description = lineItem.Description
	dbLineItem.ProposalURL = lineItem.ProposalURL
	dbLineItem.Labor = lineItem.Labor
	dbLineItem.Expenses = lineItem.Expenses
	dbLineItem.ContractorRate = lineItem.ContractorRate

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

func encodeExchangeRate(dbExchangeRate *database.ExchangeRate) ExchangeRate {
	exchangeRate := ExchangeRate{}
	exchangeRate.Month = dbExchangeRate.Month
	exchangeRate.Year = dbExchangeRate.Year
	exchangeRate.ExchangeRate = dbExchangeRate.ExchangeRate
	return exchangeRate
}

func decodeExchangeRate(exchangeRate ExchangeRate) *database.ExchangeRate {
	dbExchangeRate := &database.ExchangeRate{}
	dbExchangeRate.Month = exchangeRate.Month
	dbExchangeRate.Year = exchangeRate.Year
	dbExchangeRate.ExchangeRate = exchangeRate.ExchangeRate
	return dbExchangeRate
}

func encodePayments(dbPayments *database.Payments) Payments {
	payments := Payments{}
	payments.InvoiceToken = dbPayments.InvoiceToken
	payments.Address = dbPayments.Address
	payments.TxIDs = dbPayments.TxIDs
	payments.TimeStarted = dbPayments.TimeStarted
	payments.TimeLastUpdated = dbPayments.TimeLastUpdated
	payments.AmountNeeded = dbPayments.AmountNeeded
	payments.AmountReceived = dbPayments.AmountReceived
	payments.Status = uint(dbPayments.Status)
	return payments
}

func decodePayment(payments *Payments) database.Payments {
	dbPayments := database.Payments{}
	dbPayments.InvoiceToken = payments.InvoiceToken
	dbPayments.Address = payments.Address
	dbPayments.TxIDs = payments.TxIDs
	dbPayments.TimeStarted = payments.TimeStarted
	dbPayments.TimeLastUpdated = payments.TimeLastUpdated
	dbPayments.AmountNeeded = payments.AmountNeeded
	dbPayments.AmountReceived = payments.AmountReceived
	dbPayments.Status = cms.PaymentStatusT(payments.Status)
	return dbPayments
}

func encodeDCC(dbDCC *database.DCC) *DCC {
	dcc := DCC{
		Token:              dbDCC.Token,
		SponsorUserID:      dbDCC.SponsorUserID,
		NomineeUserID:      dbDCC.NomineeUserID,
		Type:               int(dbDCC.Type),
		Status:             int(dbDCC.Status),
		StatusChangeReason: dbDCC.StatusChangeReason,
		Timestamp:          dbDCC.Timestamp,
		PublicKey:          dbDCC.PublicKey,
		UserSignature:      dbDCC.UserSignature,
		ServerSignature:    dbDCC.ServerSignature,
		SponsorStatement:   dbDCC.SponsorStatement,
		Domain:             int(dbDCC.Domain),
		ContractorType:     int(dbDCC.ContractorType),

		SupportUserIDs:    dbDCC.SupportUserIDs,
		OppositionUserIDs: dbDCC.OppositionUserIDs,
	}
	return &dcc
}

func decodeDCC(dcc *DCC) *database.DCC {
	dbDCC := database.DCC{
		Token:              dcc.Token,
		SponsorUserID:      dcc.SponsorUserID,
		NomineeUserID:      dcc.NomineeUserID,
		Type:               cms.DCCTypeT(dcc.Type),
		Status:             cms.DCCStatusT(dcc.Status),
		StatusChangeReason: dcc.StatusChangeReason,
		Timestamp:          dcc.Timestamp,
		PublicKey:          dcc.PublicKey,
		UserSignature:      dcc.UserSignature,
		ServerSignature:    dcc.ServerSignature,
		SponsorStatement:   dcc.SponsorStatement,
		Domain:             cms.DomainTypeT(dcc.Domain),
		ContractorType:     cms.ContractorTypeT(dcc.ContractorType),

		SupportUserIDs:    dcc.SupportUserIDs,
		OppositionUserIDs: dcc.OppositionUserIDs,
	}
	return &dbDCC
}
