// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/decred/politeia/politeiad/api/v1/identity"
	cms "github.com/decred/politeia/politeiawww/api/cms/v2"
	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
	"github.com/decred/politeia/util"
)

const (
	// PolicyInvoiceCommentChar is the character which, when used as the first
	// character of a line, denotes that entire line as a comment.
	PolicyInvoiceCommentChar rune = '#'

	// PolicyInvoiceFieldDelimiterChar is the character that delimits field
	// values for each line item in the CSV.
	PolicyInvoiceFieldDelimiterChar rune = ','

	// PolicyInvoiceLineItemCount is the number of expected fields in the raw
	// csv line items
	PolicyInvoiceLineItemCount = 9
)

const (
	monthInSeconds      int64 = 30 * 24 * 60 * 60
	fourMonthsInSeconds int64 = 4 * monthInSeconds
)

func printInvoiceFiles(files []rcv1.File) error {
	for _, v := range files {
		b, err := base64.StdEncoding.DecodeString(v.Payload)
		if err != nil {
			return err
		}
		size := byteCountSI(int64(len(b)))
		printf("  %-22v %-26v %v\n", v.Name, v.MIME, size)
	}

	// Its possible for a invoice metadata to not exist if the
	// record has been censored.
	pm, err := pclient.InvoiceMetadataDecode(files)
	if err == nil {
		printf("%v\n", cms.FileNameInvoiceMetadata)
		printf("  Version                : %v\n", pm.Version)
		printf("  Month                  : %v\n", pm.Month)
		printf("  Year                   : %v\n", pm.Year)
		printf("  Exchange Rate          : %v\n", pm.ExchangeRate)
		printf("  Contractor Name        : %v\n", pm.ContractorName)
		printf("  Contractor Location    : %v\n", pm.ContractorLocation)
		printf("  Contractor Contact     : %v\n", pm.ContractorContact)
		printf("  Contractor Rate        : %v\n", pm.ContractorRate)
		printf("  Payment Address        : %v\n", pm.PaymentAddress)
	}

	return nil
}

func printInvoice(r rcv1.Record) error {
	printf("Token    : %v\n", r.CensorshipRecord.Token)
	printf("Version  : %v\n", r.Version)
	printf("State    : %v\n", rcv1.RecordStates[r.State])
	printf("Status   : %v\n", rcv1.RecordStatuses[r.Status])
	printf("Timestamp: %v\n", timestampFromUnix(r.Timestamp))
	printf("Username : %v\n", r.Username)
	printf("Merkle   : %v\n", r.CensorshipRecord.Merkle)
	printf("Receipt  : %v\n", r.CensorshipRecord.Signature)
	printf("Metadata\n")
	for _, v := range r.Metadata {
		size := byteCountSI(int64(len([]byte(v.Payload))))
		printf("  %-8v %-2v %v\n", v.PluginID, v.StreamID, size)
	}
	printf("Files\n")
	return printInvoiceFiles(r.Files)
}

// signedMerkleRoot returns the signed merkle root of the provided files. The
// signature is created using the provided identity.
func signedMerkleRoot(files []rcv1.File, fid *identity.FullIdentity) (string, error) {
	if len(files) == 0 {
		return "", fmt.Errorf("no proposal files found")
	}
	digests := make([]string, 0, len(files))
	for _, v := range files {
		digests = append(digests, v.Digest)
	}
	m, err := util.MerkleRoot(digests)
	if err != nil {
		return "", err
	}
	mr := hex.EncodeToString(m[:])
	sig := fid.SignMessage([]byte(mr))
	return hex.EncodeToString(sig[:]), nil
}

func validateParseCSV(data []byte) (*cms.InvoiceInput, error) {
	LineItemType := map[string]cms.LineItemTypeT{
		"labor":   cms.LineItemTypeLabor,
		"expense": cms.LineItemTypeExpense,
		"misc":    cms.LineItemTypeMisc,
		"sub":     cms.LineItemTypeSubHours,
	}
	invInput := &cms.InvoiceInput{}
	// Validate that the invoice is CSV-formatted.
	csvReader := csv.NewReader(strings.NewReader(string(data)))
	csvReader.Comma = PolicyInvoiceFieldDelimiterChar
	csvReader.Comment = PolicyInvoiceCommentChar
	csvReader.TrimLeadingSpace = true

	csvFields, err := csvReader.ReadAll()
	if err != nil {
		return invInput, err
	}

	lineItems := make([]cms.LineItemsInput, 0, len(csvFields))
	// Validate that line items are the correct length and contents in
	// field 4 and 5 are parsable to integers
	for i, lineContents := range csvFields {
		lineItem := cms.LineItemsInput{}
		if len(lineContents) != PolicyInvoiceLineItemCount {
			return invInput,
				fmt.Errorf("invalid number of line items on line: %v want: %v got: %v",
					i, PolicyInvoiceLineItemCount, len(lineContents))
		}
		lineItemType, ok := LineItemType[strings.ToLower(strings.TrimSpace(lineContents[0]))]
		if !ok {
			return invInput,
				fmt.Errorf("invalid line item type on line: %v", i)
		}
		hours, err := strconv.Atoi(strings.TrimSpace(lineContents[5]))
		if err != nil {
			return invInput,
				fmt.Errorf("invalid hours (%v) entered on line: %v", lineContents[5], i)
		}
		cost, err := strconv.Atoi(strings.TrimSpace(lineContents[6]))
		if err != nil {
			return invInput,
				fmt.Errorf("invalid cost (%v) entered on line: %v", lineContents[6], i)
		}
		rate, err := strconv.Atoi(strings.TrimSpace(lineContents[8]))
		if err != nil {
			return invInput,
				fmt.Errorf("invalid subrate hours (%v) entered on line: %v", lineContents[8], i)
		}

		lineItem.Type = lineItemType
		lineItem.Domain = strings.TrimSpace(lineContents[1])
		lineItem.Subdomain = strings.TrimSpace(lineContents[2])
		lineItem.Description = strings.TrimSpace(lineContents[3])
		lineItem.ProposalToken = strings.TrimSpace(lineContents[4])
		lineItem.SubUserID = strings.TrimSpace(lineContents[7])
		lineItem.SubRate = uint(rate * 100)
		lineItem.Labor = uint(hours * 60)
		lineItem.Expenses = uint(cost * 100)
		lineItems = append(lineItems, lineItem)
	}
	invInput.LineItems = lineItems

	return invInput, nil
}
