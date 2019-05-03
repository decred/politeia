// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/decred/dcrtime/merkle"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/api/v1/mime"
	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/util"
)

func createValidLineItems(t *testing.T) []cms.LineItemsInput {
	t.Helper()

	// valid line item entries
	lineItemLabor := cms.LineItemsInput{
		Type:          cms.LineItemTypeLabor,
		Domain:        "Development",
		Subdomain:     "politeia",
		Description:   "PR #1",
		ProposalToken: "",
		Labor:         40,
		Expenses:      0,
	}
	lineItemExpense := cms.LineItemsInput{
		Type:          cms.LineItemTypeExpense,
		Domain:        "Design",
		Subdomain:     "pgui",
		Description:   "Artwork",
		ProposalToken: "",
		Labor:         0,
		Expenses:      1000,
	}
	lineItemMisc := cms.LineItemsInput{
		Type:          cms.LineItemTypeMisc,
		Domain:        "Research",
		Subdomain:     "dcrd",
		Description:   "reorg",
		ProposalToken: "",
		Labor:         0,
		Expenses:      10000,
	}

	return []cms.LineItemsInput{
		lineItemLabor,
		lineItemExpense,
		lineItemMisc,
	}
}

func createInvoiceInput(t *testing.T, li []cms.LineItemsInput) cms.InvoiceInput {
	t.Helper()

	var (
		month       uint = 2
		year        uint = 2019
		rate        uint = 4000
		monthAvg    uint = 1651
		name             = "test"
		location         = "testlocation"
		contact          = "test@gmail.com"
		paymentaddr      = "DsUHkmH555D4tLQi5ap4gVAV86tVN29nqYi"
	)

	return cms.InvoiceInput{
		Version:            1,
		Month:              month,
		Year:               year,
		ExchangeRate:       monthAvg,
		ContractorName:     name,
		ContractorLocation: location,
		ContractorContact:  contact,
		ContractorRate:     rate,
		PaymentAddress:     paymentaddr,
		LineItems:          li,
	}
}

// createInvoiceJSON creates an index file with the passed InvoiceInput
func createInvoiceJSON(t *testing.T, ii cms.InvoiceInput) *www.File {
	t.Helper()

	file, _ := json.Marshal(ii)

	return &www.File{
		Name:    invoiceFile,
		MIME:    mime.DetectMimeType(file),
		Digest:  hex.EncodeToString(util.Digest(file)),
		Payload: base64.StdEncoding.EncodeToString(file),
	}
}

// createNewInvoice computes the merkle root of the given files, signs the
// merkle root with the given identity then returns a NewInvoice object.
func createNewInvoice(t *testing.T, id *identity.FullIdentity,
	files []www.File, month uint, year uint) *cms.NewInvoice {

	t.Helper()

	if len(files) == 0 {
		t.Fatalf("no files found")
	}

	// Compute merkle
	digests := make([]*[sha256.Size]byte, 0, len(files))
	for _, f := range files {
		d, ok := util.ConvertDigest(f.Digest)
		if !ok {
			t.Fatalf("could not convert digest %v", f.Digest)
		}
		digests = append(digests, &d)
	}
	root := hex.EncodeToString(merkle.Root(digests)[:])

	// Sign merkle
	sig := id.SignMessage([]byte(root))

	return &cms.NewInvoice{
		Month:     month,
		Year:      year,
		Files:     files,
		PublicKey: hex.EncodeToString(id.Public.Key[:]),
		Signature: hex.EncodeToString(sig[:]),
	}
}

// Invoice Validation Tests
func TestValidateInvoice(t *testing.T) {
	p, cleanup := newTestPoliteiawww(t, cmsWWWMode)
	defer cleanup()

	usr, id := newUser(t, p, true, false)

	vli := createValidLineItems(t)
	ii := createInvoiceInput(t, vli)
	json := createInvoiceJSON(t, ii)
	png := createFilePNG(t, false)
	md := newFileRandomMD(t)
	ni := createNewInvoice(t, id, []www.File{*json, *png}, ii.Month, ii.Year)

	// Invalid signature test
	invoiceInvalidSig := &cms.NewInvoice{
		Month:     ni.Month,
		Year:      ni.Year,
		Files:     ni.Files,
		PublicKey: ni.PublicKey,
		Signature: "invalid",
	}

	// Incorrect signature test
	invoiceIncorrectSig := createNewInvoice(t, id, []www.File{*json},
		ii.Month, ii.Year)
	invoiceIncorrectSig.Signature = ni.Signature

	// No index file test
	invoiceNoIndexFile := &cms.NewInvoice{
		Month:     ni.Month,
		Year:      ni.Year,
		Files:     make([]www.File, 0),
		PublicKey: ni.PublicKey,
		Signature: ni.Signature,
	}

	// Invalid index mime type test
	indexJpeg := createFileJPEG(t, invoiceFile)
	invoiceInvalidIndexMimeType := createNewInvoice(t, id,
		[]www.File{*indexJpeg}, ii.Month, ii.Year)

	// Index file too large test.
	// It creates a valid line item input, but too large to be accepted
	lineItemLabor := cms.LineItemsInput{
		Type:          cms.LineItemTypeLabor,
		Domain:        "Development",
		Subdomain:     "politeia",
		Description:   "PR #2",
		ProposalToken: "",
		Labor:         20,
		Expenses:      0,
	}
	tooManyLineItems := make([]cms.LineItemsInput, 0, 5000)
	for i := 0; i < 5000; i++ {
		tooManyLineItems = append(tooManyLineItems, lineItemLabor)
	}
	invalidInvoiceInput := createInvoiceInput(t, tooManyLineItems)
	jsonLarge := createInvoiceJSON(t, invalidInvoiceInput)
	invoiceIndexLarge := createNewInvoice(t, id, []www.File{*jsonLarge},
		ii.Month, ii.Year)

	// Too many index files test
	invoiceMaxIndexFiles := createNewInvoice(t, id, []www.File{*json, *json},
		ii.Month, ii.Year)

	// Attachment file too large test
	fileLarge := createFilePNG(t, true)
	invoiceAttachmentLarge := createNewInvoice(t, id,
		[]www.File{*json, *fileLarge}, ii.Month, ii.Year)

	// Too many attached files test
	files := make([]www.File, 0, cms.PolicyMaxAttachments+1)
	files = append(files, *json)
	for i := 0; i < cms.PolicyMaxAttachments+1; i++ {
		m := md
		m.Name = fmt.Sprintf("%v.md", i)
		files = append(files, m)
	}
	invoiceMaxAttachments := createNewInvoice(t, id, files, ii.Month, ii.Year)

	// Setup test cases
	var tests = []struct {
		name       string
		newInvoice cms.NewInvoice
		user       *user.User
		want       error
	}{
		{"correct invoice", *ni, usr, nil},

		{"invalid signature", *invoiceInvalidSig, usr,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidSignature,
			}},

		{"incorrect signature", *invoiceIncorrectSig, usr,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidSignature,
			}},

		{"no index file", *invoiceNoIndexFile, usr,
			www.UserError{
				ErrorCode: www.ErrorStatusNoIndexFile,
			}},

		{"invalid index mime type", *invoiceInvalidIndexMimeType, usr,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidMIMEType,
			}},

		{"index file too large", *invoiceIndexLarge, usr,
			www.UserError{
				ErrorCode: www.ErrorStatusMaxIndexFileSizeExceededPolicy,
			}},

		{"too many index files", *invoiceMaxIndexFiles, usr,
			www.UserError{
				ErrorCode: www.ErrorStatusMaxIndexFileExceededPolicy,
			}},

		{"attachment file too large", *invoiceAttachmentLarge, usr,
			www.UserError{
				ErrorCode: www.ErrorStatusMaxAttachmentSizeExceededPolicy,
			}},

		{"too many attached files", *invoiceMaxAttachments, usr,
			www.UserError{
				ErrorCode: www.ErrorStatusMaxAttachmentsExceededPolicy,
			}},
	}

	// Run test cases
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := p.validateInvoice(test.newInvoice, test.user)
			got := errToStr(err)
			want := errToStr(test.want)
			if got != want {
				t.Errorf("got %v, want %v", got, want)
			}
		})
	}
}
