// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cms

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"image"
	"image/png"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/plugins/cms"
	"github.com/decred/politeia/politeiad/plugins/comments"
	"github.com/decred/politeia/util"
)

func TestIsInCommentTree(t *testing.T) {
	// Setup test data
	oneNodeTree := []comments.Comment{
		{
			CommentID: 1,
			ParentID:  0,
		},
	}

	twoLeafsTree := []comments.Comment{
		{
			CommentID: 1,
			ParentID:  0,
		},
		{
			CommentID: 2,
			ParentID:  0,
		},
	}

	threeLevelsTree := []comments.Comment{
		{
			CommentID: 1,
			ParentID:  0,
		},
		{
			CommentID: 2,
			ParentID:  1,
		},
		{
			CommentID: 3,
			ParentID:  2,
		},
		{
			CommentID: 4,
			ParentID:  0,
		},
	}

	sixLevelsTree := []comments.Comment{
		{
			CommentID: 1,
			ParentID:  0,
		},
		{
			CommentID: 2,
			ParentID:  1,
		},
		{
			CommentID: 3,
			ParentID:  1,
		},
		{
			CommentID: 4,
			ParentID:  2,
		},
		{
			CommentID: 5,
			ParentID:  2,
		},
		{
			CommentID: 6,
			ParentID:  3,
		},
		{
			CommentID: 7,
			ParentID:  5,
		},
		{
			CommentID: 8,
			ParentID:  5,
		},
		{
			CommentID: 9,
			ParentID:  8,
		},
		{
			CommentID: 10,
			ParentID:  9,
		},
	}

	// Setup tests
	var tests = []struct {
		name string // Test name
		rootID,
		childID uint32
		comments []comments.Comment
		res      bool // Expected result
	}{
		{
			name:     "one node tree true case",
			rootID:   1,
			childID:  1,
			comments: oneNodeTree,
			res:      true,
		},
		{
			name:     "one node tree false case",
			rootID:   0,
			childID:  1,
			comments: oneNodeTree,
			res:      false,
		},
		{
			name:     "two leafs tree false case",
			rootID:   1,
			childID:  2,
			comments: twoLeafsTree,
			res:      false,
		},
		{
			name:     "three levels tree true case",
			rootID:   1,
			childID:  3,
			comments: threeLevelsTree,
			res:      true,
		},
		{
			name:     "three levels tree false case",
			rootID:   1,
			childID:  4,
			comments: threeLevelsTree,
			res:      false,
		},
		{
			name:     "six levels tree true case",
			rootID:   1,
			childID:  10,
			comments: sixLevelsTree,
			res:      true,
		},
		{
			name:     "six levels tree false case",
			rootID:   6,
			childID:  10,
			comments: sixLevelsTree,
			res:      false,
		},
	}

	// Run tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := isInCommentTree(tc.rootID, tc.childID, tc.comments)
			if res != tc.res {
				// Unexpected result
				t.Errorf("unexpected result; wanted '%v', got '%v'", tc.res, res)
				return
			}
		})
	}
}

func TestHookNewRecordPre(t *testing.T) {
	// Setup cms plugin
	p, cleanup := newTestCmsPlugin(t)
	defer cleanup()

	// Run tests
	runInvoiceFormatTests(t, p.hookNewRecordPre)
}

func TestHookEditRecordPre(t *testing.T) {
	// Setup cms plugin
	p, cleanup := newTestCmsPlugin(t)
	defer cleanup()

	// Run tests
	runInvoiceFormatTests(t, p.hookEditRecordPre)
}

// runInvoiceFormatTests runs the invoice format tests using the provided
// hook function as the test function. This allows us to run the same set of
// formatting tests of multiple hooks without needing to duplicate the setup
// and error handling code.
func runInvoiceFormatTests(t *testing.T, hookFn func(string) error) {
	for _, v := range invoiceFormatTests(t) {
		t.Run(v.name, func(t *testing.T) {
			// Decode the expected error into a PluginError. If
			// an error is being returned it should always be a
			// PluginError.
			var wantErrorCode cms.ErrorCodeT
			if v.err != nil {
				var pe backend.PluginError
				if !errors.As(v.err, &pe) {
					t.Fatalf("error is not a plugin error '%v'", v.err)
				}
				wantErrorCode = cms.ErrorCodeT(pe.ErrorCode)
			}

			// Setup payload
			hnrp := plugins.HookNewRecordPre{
				Files: v.files,
			}
			b, err := json.Marshal(hnrp)
			if err != nil {
				t.Fatal(err)
			}
			payload := string(b)

			// Run test
			err = hookFn(payload)
			switch {
			case v.err != nil && err == nil:
				// Wanted an error but didn't get one
				t.Errorf("want error '%v', got nil",
					cms.ErrorCodes[wantErrorCode])
				return

			case v.err == nil && err != nil:
				// Wanted success but got an error
				t.Errorf("want error nil, got '%v'", err)
				return

			case v.err != nil && err != nil:
				// Wanted an error and got an error. Verify that it's
				// the correct error. All errors should be backend
				// plugin errors.
				var gotErr backend.PluginError
				if !errors.As(err, &gotErr) {
					t.Errorf("want plugin error, got '%v'", err)
					return
				}
				if cms.PluginID != gotErr.PluginID {
					t.Errorf("want plugin error with plugin ID '%v', got '%v'",
						cms.PluginID, gotErr.PluginID)
					return
				}

				gotErrorCode := cms.ErrorCodeT(gotErr.ErrorCode)
				if wantErrorCode != gotErrorCode {
					t.Errorf("want error '%v', got '%v'",
						cms.ErrorCodes[wantErrorCode],
						cms.ErrorCodes[gotErrorCode])
				}

				// Success; continue to next test
				return

			case v.err == nil && err == nil:
				// Success; continue to next test
				return
			}
		})
	}
}

// invoiceFormatTest contains the input and output for a test that verifies
// the invoice format meets the cms plugin requirements.
type invoiceFormatTest struct {
	name  string         // Test name
	files []backend.File // Input
	err   error          // Expected output
}

// invoiceFormatTests returns a list of tests that verify the files of a
// invoice meet all formatting criteria that the cms plugin requires.
func invoiceFormatTests(t *testing.T) []invoiceFormatTest {
	t.Helper()

	testInvoice, err := fileInvoiceIndex()
	if err != nil {
		t.Fatal(err)
	}
	// Setup test files
	var (
		index         = testInvoice
		indexTooLarge backend.File
		png           backend.File
		pngTooLarge   backend.File
	)

	// Create a index file that is too large
	var sb strings.Builder
	for i := 0; i <= int(cms.SettingTextFileSizeMax); i++ {
		sb.WriteString("a")
	}
	indexTooLarge = file(index.Name, []byte(sb.String()))

	// Load test fixtures
	b, err := ioutil.ReadFile("testdata/valid.png")
	if err != nil {
		t.Fatal(err)
	}
	png = file("valid.png", b)

	b, err = ioutil.ReadFile("testdata/too-large.png")
	if err != nil {
		t.Fatal(err)
	}
	pngTooLarge = file("too-large.png", b)

	// Setup tests
	tests := []invoiceFormatTest{
		{
			"text file name invalid",
			[]backend.File{
				{
					Name:    "notallowed.txt",
					MIME:    index.MIME,
					Digest:  index.Digest,
					Payload: index.Payload,
				},
				fileInvoiceMetadata(t, nil),
			},
			backend.PluginError{
				PluginID:  cms.PluginID,
				ErrorCode: uint32(cms.ErrorCodeTextFileNameInvalid),
			},
		},
		{
			"text file too large",
			[]backend.File{
				indexTooLarge,
				fileInvoiceMetadata(t, nil),
			},
			backend.PluginError{
				PluginID:  cms.PluginID,
				ErrorCode: uint32(cms.ErrorCodeTextFileSizeInvalid),
			},
		},
		{
			"image file too large",
			[]backend.File{
				index,
				fileInvoiceMetadata(t, nil),
				pngTooLarge,
			},
			backend.PluginError{
				PluginID:  cms.PluginID,
				ErrorCode: uint32(cms.ErrorCodeImageFileSizeInvalid),
			},
		},
		{
			"index file missing",
			[]backend.File{
				fileInvoiceMetadata(t, nil),
			},
			backend.PluginError{
				PluginID:  cms.PluginID,
				ErrorCode: uint32(cms.ErrorCodeTextFileMissing),
			},
		},
		{
			"too many images",
			[]backend.File{
				index,
				fileInvoiceMetadata(t, nil),
				fileEmptyPNG(t), fileEmptyPNG(t), fileEmptyPNG(t),
				fileEmptyPNG(t), fileEmptyPNG(t), fileEmptyPNG(t),
			},
			backend.PluginError{
				PluginID:  cms.PluginID,
				ErrorCode: uint32(cms.ErrorCodeImageFileCountInvalid),
			},
		},
		{
			"invoice metadata missing",
			[]backend.File{
				index,
			},
			backend.PluginError{
				PluginID:  cms.PluginID,
				ErrorCode: uint32(cms.ErrorCodeTextFileMissing),
			},
		},
		{
			"success no attachments",
			[]backend.File{
				index,
				fileInvoiceMetadata(t, nil),
			},
			nil,
		},
		{
			"success with attachments",
			[]backend.File{
				index,
				fileInvoiceMetadata(t, nil),
				png,
			},
			nil,
		},
	}

	tests = append(tests, invoiceNameTests(t)...)
	//tests = append(tests, invoiceDomainTests(t)...)
	return tests
}

// invoiceNameTests returns a list of tests that verify the invoice name
// requirements.
func invoiceNameTests(t *testing.T) []invoiceFormatTest {
	t.Helper()

	// Create names to test min and max lengths
	var (
		nameTooShort  string
		nameTooLong   string
		nameMinLength string
		nameMaxLength string

		b strings.Builder
	)
	for i := 0; i < int(cms.SettingNameLengthMin)-1; i++ {
		b.WriteString("a")
	}
	nameTooShort = b.String()
	b.Reset()

	for i := 0; i < int(cms.SettingNameLengthMax)+1; i++ {
		b.WriteString("a")
	}
	nameTooLong = b.String()
	b.Reset()

	for i := 0; i < int(cms.SettingNameLengthMin); i++ {
		b.WriteString("a")
	}
	nameMinLength = b.String()
	b.Reset()

	for i := 0; i < int(cms.SettingNameLengthMax); i++ {
		b.WriteString("a")
	}
	nameMaxLength = b.String()

	// Setup files with an empty invoice name. This is done manually
	// because the function that creates the invoice metadata uses
	// a default value when the name is provided as an empty string.
	filesEmptyName := filesForInvoice(t, &cms.InvoiceMetadata{
		ContractorName: "",
	})
	for k, v := range filesEmptyName {
		if v.Name == cms.FileNameInvoiceMetadata {
			b, err := base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				t.Fatal(err)
			}
			var pm cms.InvoiceMetadata
			err = json.Unmarshal(b, &pm)
			if err != nil {
				t.Fatal(err)
			}
			pm.ContractorName = ""
			b, err = json.Marshal(pm)
			if err != nil {
				t.Fatal(err)
			}
			v.Payload = base64.StdEncoding.EncodeToString(b)
			filesEmptyName[k] = v
		}
	}

	// errNameInvalid is returned when invoice name validation
	// fails.
	errNameInvalid := backend.PluginError{
		PluginID:  cms.PluginID,
		ErrorCode: uint32(cms.ErrorStatusMalformedName),
	}
	// errNameMissing is returned when invoice name is missing
	errNameMissing := backend.PluginError{
		PluginID:  cms.PluginID,
		ErrorCode: uint32(cms.ErrorStatusInvoiceMissingName),
	}
	return []invoiceFormatTest{
		{
			"contractor name is empty",
			filesEmptyName,
			errNameMissing,
		},
		{
			"contractor name is too short",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorName: nameTooShort,
			}),
			errNameInvalid,
		},
		{
			"contractor name is too long",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorName: nameTooLong,
			}),
			errNameInvalid,
		},
		{
			"contractor name is the min length",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorName: nameMinLength,
			}),
			nil,
		},
		{
			"contractor name is the max length",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorName: nameMaxLength,
			}),
			nil,
		},
		{
			"contractor name contains A to Z",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorName: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
			}),
			nil,
		},
		{
			"contractor name contains a to z",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorName: "abcdefghijklmnopqrstuvwxyz",
			}),
			nil,
		},
		{
			"contractor name contains 0 to 9",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorName: "0123456789",
			}),
			nil,
		},
		{
			"contractor name contains supported chars",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorName: ".a-b,a",
			}),
			nil,
		},
		{
			"contractor name contains non-supported chars",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorName: "&.,:;- @+#/()!?\"'",
			}),
			errNameInvalid,
		},
		{
			"contractor name contains newline",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorName: "invoice name\n",
			}),
			errNameInvalid,
		},
		{
			"contractor name contains tab",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorName: "invoice name\t",
			}),
			errNameInvalid,
		},
		{
			"contractor name contains brackets",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorName: "{invoice name}",
			}),
			errNameInvalid,
		},
		{
			"contractor name is valid lowercase",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorName: "invoice name",
			}),
			nil,
		},
		{
			"contractor name is valid mixed case",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorName: "Invoice Name",
			}),
			nil,
		},
	}
}

/*
// invoiceAmountTests returns a list of tests that verify the invoice
// amount requirements.
func invoiceAmountTests(t *testing.T) []invoiceFormatTest {
	t.Helper()

	// amount values to test min & max amount limits
	var (
		amountMin      = cms.SettingInvoiceAmountMin
		amountMax      = cms.SettingInvoiceAmountMax
		amountTooSmall = amountMin - 1
		amountTooBig   = amountMax + 1
	)

	// Setup files with a zero amount. This is done manually
	// because the function that creates the invoice metadata uses
	// a default value when the amount is provided as zero.
	filesZeroAmount := filesForInvoice(t, &cms.InvoiceMetadata{
		Amount: 0,
	})
	for k, v := range filesZeroAmount {
		if v.Name == cms.FileNameInvoiceMetadata {
			b, err := base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				t.Fatal(err)
			}
			var pm cms.InvoiceMetadata
			err = json.Unmarshal(b, &pm)
			if err != nil {
				t.Fatal(err)
			}
			pm.Amount = 0
			b, err = json.Marshal(pm)
			if err != nil {
				t.Fatal(err)
			}
			v.Payload = base64.StdEncoding.EncodeToString(b)
			filesZeroAmount[k] = v
		}
	}

	// errAmountInvalid is returned when invoice amount
	// validation fails.
	errAmountInvalid := backend.PluginError{
		PluginID:  cms.PluginID,
		ErrorCode: uint32(cms.ErrorCodeInvoiceAmountInvalid),
	}

	return []invoiceFormatTest{
		{
			"amount is zero",
			filesZeroAmount,
			errAmountInvalid,
		},
		{
			"amount too small",
			filesForInvoice(t, &cms.InvoiceMetadata{
				Amount: amountTooSmall,
			}),
			errAmountInvalid,
		},
		{
			"amount too big",
			filesForInvoice(t, &cms.InvoiceMetadata{
				Amount: amountTooBig,
			}),
			errAmountInvalid,
		},
		{
			"min amount",
			filesForInvoice(t, &cms.InvoiceMetadata{
				Amount: amountMin,
			}),
			nil,
		},
		{
			"max amount",
			filesForInvoice(t, &cms.InvoiceMetadata{
				Amount: amountMax,
			}),
			nil,
		},
	}
}

// invoiceStartDateTests returns a list of tests that verify the invoice
// start date requirements.
func invoiceStartDateTests(t *testing.T) []invoiceFormatTest {
	t.Helper()

	// Start date values to test min start date
	var (
		sDateInPast      = time.Now().Unix() - 172800  // two days ago
		sDateInTwoMonths = time.Now().Unix() + 5256000 // in 2 months
	)

	// Setup files with a zero start date. This is done manually
	// because the function that creates the invoice metadata uses
	// a default value when the start date is provided as zero.
	filesZeroStartDate := filesForInvoice(t, &cms.InvoiceMetadata{
		StartDate: 0,
	})
	for k, v := range filesZeroStartDate {
		if v.Name == cms.FileNameInvoiceMetadata {
			b, err := base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				t.Fatal(err)
			}
			var pm cms.InvoiceMetadata
			err = json.Unmarshal(b, &pm)
			if err != nil {
				t.Fatal(err)
			}
			pm.StartDate = 0
			b, err = json.Marshal(pm)
			if err != nil {
				t.Fatal(err)
			}
			v.Payload = base64.StdEncoding.EncodeToString(b)
			filesZeroStartDate[k] = v
		}
	}

	// errStartDateInvalid is returned when invoice start date
	// validation fails.
	errStartDateInvalid := backend.PluginError{
		PluginID:  cms.PluginID,
		ErrorCode: uint32(cms.ErrorCodeInvoiceStartDateInvalid),
	}

	return []invoiceFormatTest{
		{
			"start date in the past",
			filesForInvoice(t, &cms.InvoiceMetadata{
				StartDate: sDateInPast,
			}),
			errStartDateInvalid,
		},
		{
			"start date is zero",
			filesZeroStartDate,
			errStartDateInvalid,
		},
		{
			"start date in two months",
			filesForInvoice(t, &cms.InvoiceMetadata{
				StartDate: sDateInTwoMonths,
			}),
			nil,
		},
	}
}

// invoiceEndDateTests returns a list of tests that verify the invoice
// end date requirements.
func invoiceEndDateTests(t *testing.T) []invoiceFormatTest {
	t.Helper()

	// End date values to test end date validations.
	var (
		now                  = time.Now().Unix()
		eDateInPast          = now - 172800 // two days ago
		eDateBeforeStartDate = now + 172800 // in two days
		eDateAfterMax        = now +
			cms.SettingInvoiceEndDateMax + 60 // 1 minute after max
		eDateInEightMonths = now + 21040000 // in 8 months
	)

	// Setup files with a zero end date. This is done manually
	// because the function that creates the invoice metadata uses
	// a default value when the end date is provided as zero.
	filesZeroEndDate := filesForInvoice(t, &cms.InvoiceMetadata{
		EndDate: 0,
	})
	for k, v := range filesZeroEndDate {
		if v.Name == cms.FileNameInvoiceMetadata {
			b, err := base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				t.Fatal(err)
			}
			var pm cms.InvoiceMetadata
			err = json.Unmarshal(b, &pm)
			if err != nil {
				t.Fatal(err)
			}
			pm.EndDate = 0
			b, err = json.Marshal(pm)
			if err != nil {
				t.Fatal(err)
			}
			v.Payload = base64.StdEncoding.EncodeToString(b)
			filesZeroEndDate[k] = v
		}
	}

	// errEndDateInvalid is returned when invoice end date
	// validation fails.
	errEndDateInvalid := backend.PluginError{
		PluginID:  cms.PluginID,
		ErrorCode: uint32(cms.ErrorCodeInvoiceEndDateInvalid),
	}

	return []invoiceFormatTest{
		{
			"end date in the past",
			filesForInvoice(t, &cms.InvoiceMetadata{
				EndDate: eDateInPast,
			}),
			errEndDateInvalid,
		},
		{
			"start date is zero",
			filesZeroEndDate,
			errEndDateInvalid,
		},
		{
			"end date is before default start date",
			filesForInvoice(t, &cms.InvoiceMetadata{
				EndDate: eDateBeforeStartDate,
			}),
			errEndDateInvalid,
		},
		{
			"end date is after max",
			filesForInvoice(t, &cms.InvoiceMetadata{
				EndDate: eDateAfterMax,
			}),
			errEndDateInvalid,
		},
		{
			"end date is in 8 months",
			filesForInvoice(t, &cms.InvoiceMetadata{
				EndDate: eDateInEightMonths,
			}),
			nil,
		},
	}
}
// invoiceDomainTests returns a list of tests that verify the invoice
// domain requirements.
func invoiceDomainTests(t *testing.T) []invoiceFormatTest {
	t.Helper()

	// Domain values to test domain validations.
	var (
		validDomain   = cms.SettingInvoiceDomains[0]
		invalidDomain = "invalid-domain"
	)

	// Setup files with an empty domain. This is done manually
	// because the function that creates the invoice metadata uses
	// a default value when the domain is provided as empty string.
	filesEmptyDomain := filesForInvoice(t, &cms.InvoiceMetadata{
		Domain: "",
	})
	for k, v := range filesEmptyDomain {
		if v.Name == cms.FileNameInvoiceMetadata {
			b, err := base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				t.Fatal(err)
			}
			var pm cms.InvoiceMetadata
			err = json.Unmarshal(b, &pm)
			if err != nil {
				t.Fatal(err)
			}
			pm.Domain = ""
			b, err = json.Marshal(pm)
			if err != nil {
				t.Fatal(err)
			}
			v.Payload = base64.StdEncoding.EncodeToString(b)
			filesEmptyDomain[k] = v
		}
	}

	// errDomainInvalid is returned when invoice domain
	// validation fails.
	errDomainInvalid := backend.PluginError{
		PluginID:  cms.PluginID,
		ErrorCode: uint32(cms.ErrorCodeInvoiceDomainInvalid),
	}

	return []invoiceFormatTest{
		{
			"invalid domain",
			filesForInvoice(t, &cms.InvoiceMetadata{
				Domain: invalidDomain,
			}),
			errDomainInvalid,
		},
		{
			"empty domain",
			filesEmptyDomain,
			errDomainInvalid,
		},
		{
			"valid domain",
			filesForInvoice(t, &cms.InvoiceMetadata{
				Domain: validDomain,
			}),
			nil,
		},
	}
}

*/
// file returns a backend file for the provided data.
func file(name string, payload []byte) backend.File {
	return backend.File{
		Name:    name,
		MIME:    http.DetectContentType(payload),
		Digest:  hex.EncodeToString(util.Digest(payload)),
		Payload: base64.StdEncoding.EncodeToString(payload),
	}
}

// fileInvoiceIndex returns a backend file that contains a invoice index
// file.
func fileInvoiceIndex() (backend.File, error) {

	testInvoice := cms.InvoiceInput{}

	testLineItems := make([]cms.LineItemsInput, 2)
	testLineItems[0] = cms.LineItemsInput{
		Type:          cms.LineItemTypeLabor,
		Domain:        "development",
		Subdomain:     "",
		Description:   "this is the first line description.",
		ProposalToken: "",
		SubUserID:     "",
		SubRate:       0,
		Labor:         1000,
		Expenses:      0,
	}
	testLineItems[1] = cms.LineItemsInput{
		Type:          cms.LineItemTypeLabor,
		Domain:        "development",
		Subdomain:     "sub",
		Description:   "this is the second line description.",
		ProposalToken: "",
		SubUserID:     "",
		SubRate:       0,
		Labor:         1000,
		Expenses:      0,
	}
	testInvoice.LineItems = testLineItems

	// Create a raw json []byte from the above information
	b, err := json.Marshal(testInvoice)
	if err != nil {
		return backend.File{}, err
	}
	return file(cms.FileNameIndexFile, b), nil
}

// fileInvoiceMetadata returns a backend file that contains a invoice
// metadata file. The invoice metadata can optionally be provided as an
// argument. Any required invoice metadata fields that are not provided by
// the caller will be filled in using valid defaults.
func fileInvoiceMetadata(t *testing.T, pm *cms.InvoiceMetadata) backend.File {
	t.Helper()

	// Setup a default invoice metadata
	pmd := &cms.InvoiceMetadata{
		Name:               "Test Invoice Name",
		Domain:             "development",
		Month:              3,
		Year:               2021,
		ExchangeRate:       10000,
		ContractorName:     "Test McTesterson",
		ContractorLocation: "TestVille, USA",
		ContractorContact:  "test@decred.org",
		ContractorRate:     5000,
		PaymentAddress:     "TskbfyX1zjCwMJuYJgzqc9msC9R66ScmWti",
	}

	// Sanity check. Verify that the default domain we used is
	// one of the default domains defined by the cms plugin API.
	var found bool
	for _, v := range cms.SettingInvoiceDomains {
		if v == pmd.Domain {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("%v is not a default domain", pmd.Domain)
	}

	// Overwrite the default values with the caller provided
	// values if they exist.
	if pm == nil {
		pm = &cms.InvoiceMetadata{}
	}
	if pm.ContractorName != "" {
		pmd.ContractorName = pm.ContractorName
	}
	if pm.ContractorContact != "" {
		pmd.ContractorContact = pm.ContractorContact
	}
	if pm.ContractorLocation != "" {
		pmd.ContractorLocation = pm.ContractorLocation
	}
	if pm.ExchangeRate != 0 {
		pmd.ExchangeRate = pm.ExchangeRate
	}
	if pm.ContractorRate != 0 {
		pmd.ContractorRate = pm.ContractorRate
	}
	if pm.PaymentAddress != "" {
		pmd.PaymentAddress = pm.PaymentAddress
	}

	// Setup and return the backend file
	b, err := json.Marshal(&pmd)
	if err != nil {
		t.Fatal(err)
	}

	return file(cms.FileNameInvoiceMetadata, b)
}

// fileEmptyPNG returns a backend File that contains an empty PNG image. The
// file name is randomly generated.
func fileEmptyPNG(t *testing.T) backend.File {
	t.Helper()

	var (
		b   = new(bytes.Buffer)
		img = image.NewRGBA(image.Rect(0, 0, 1000, 500))
	)
	err := png.Encode(b, img)
	if err != nil {
		t.Fatal(err)
	}
	r, err := util.Random(8)
	if err != nil {
		t.Fatal(err)
	}
	name := hex.EncodeToString(r) + ".png"

	return file(name, b.Bytes())
}

// filesForInvoice returns the backend files for a valid invoice. The
// returned files only include the files required by the cms plugin API. No
// attachment files are included. The caller can pass in additional files that
// will be included in the returned list.
func filesForInvoice(t *testing.T, pm *cms.InvoiceMetadata, files ...backend.File) []backend.File {
	t.Helper()
	index, err := fileInvoiceIndex()
	if err != nil {
		t.Fatal(err)
	}
	fs := []backend.File{
		index,
		fileInvoiceMetadata(t, pm),
	}
	fs = append(fs, files...)

	return fs
}
