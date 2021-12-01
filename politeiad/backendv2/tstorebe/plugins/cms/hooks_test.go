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
	"time"

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

	// Setup test files
	var (
		index         = fileInvoiceIndex(t, nil)
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
	tests = append(tests, invoiceLocationTests(t)...)
	tests = append(tests, invoiceContactTests(t)...)
	tests = append(tests, invoiceRateTests(t)...)
	tests = append(tests, invoicePaymentAddressTests(t)...)
	tests = append(tests, invoiceMonthYearTests(t)...)
	tests = append(tests, invoiceExchangeRateTests(t)...)
	tests = append(tests, lineItemTests(t)...)
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
	}, nil)
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
			}, nil),
			errNameInvalid,
		},
		{
			"contractor name is too long",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorName: nameTooLong,
			}, nil),
			errNameInvalid,
		},
		{
			"contractor name is the min length",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorName: nameMinLength,
			}, nil),
			nil,
		},
		{
			"contractor name is the max length",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorName: nameMaxLength,
			}, nil),
			nil,
		},
		{
			"contractor name contains A to Z",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorName: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
			}, nil),
			nil,
		},
		{
			"contractor name contains a to z",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorName: "abcdefghijklmnopqrstuvwxyz",
			}, nil),
			nil,
		},
		{
			"contractor name contains 0 to 9",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorName: "0123456789",
			}, nil),
			nil,
		},
		{
			"contractor name contains supported chars",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorName: ".a-b,a",
			}, nil),
			nil,
		},
		{
			"contractor name contains non-supported chars",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorName: "&.,:;- @+#/()!?\"'",
			}, nil),
			errNameInvalid,
		},
		{
			"contractor name contains newline",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorName: "invoice name\n",
			}, nil),
			errNameInvalid,
		},
		{
			"contractor name contains tab",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorName: "invoice name\t",
			}, nil),
			errNameInvalid,
		},
		{
			"contractor name contains brackets",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorName: "{invoice name}",
			}, nil),
			errNameInvalid,
		},
		{
			"contractor name is valid lowercase",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorName: "invoice name",
			}, nil),
			nil,
		},
		{
			"contractor name is valid mixed case",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorName: "Invoice Name",
			}, nil),
			nil,
		},
	}
}

// invoiceLocationTests returns a list of tests that verify the invoice location
// requirements.
func invoiceLocationTests(t *testing.T) []invoiceFormatTest {
	t.Helper()

	// Create locations to test min and max lengths
	var (
		locationTooShort  string
		locationTooLong   string
		locationMinLength string
		locationMaxLength string

		b strings.Builder
	)
	for i := 0; i < int(cms.SettingLocationLengthMin)-1; i++ {
		b.WriteString("a")
	}
	locationTooShort = b.String()
	b.Reset()

	for i := 0; i < int(cms.SettingLocationLengthMax)+1; i++ {
		b.WriteString("a")
	}
	locationTooLong = b.String()
	b.Reset()

	for i := 0; i < int(cms.SettingLocationLengthMin); i++ {
		b.WriteString("a")
	}
	locationMinLength = b.String()
	b.Reset()

	for i := 0; i < int(cms.SettingLocationLengthMax); i++ {
		b.WriteString("a")
	}
	locationMaxLength = b.String()

	// errLocationInvalid is returned when invoice location validation
	// fails.
	errLocationInvalid := backend.PluginError{
		PluginID:  cms.PluginID,
		ErrorCode: uint32(cms.ErrorStatusMalformedLocation),
	}
	return []invoiceFormatTest{
		{
			"contractor location is too short",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorLocation: locationTooShort,
			}, nil),
			errLocationInvalid,
		},
		{
			"contractor location is too long",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorLocation: locationTooLong,
			}, nil),
			errLocationInvalid,
		},
		{
			"contractor location is the min length",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorLocation: locationMinLength,
			}, nil),
			nil,
		},
		{
			"contractor location is the max length",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorLocation: locationMaxLength,
			}, nil),
			nil,
		},
		{
			"contractor location contains A to Z",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorLocation: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
			}, nil),
			nil,
		},
		{
			"contractor location contains a to z",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorLocation: "abcdefghijklmnopqrstuvwxyz",
			}, nil),
			nil,
		},
		{
			"contractor location contains 0 to 9",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorLocation: "0123456789",
			}, nil),
			nil,
		},
		{
			"contractor location contains supported chars",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorLocation: ".a-b,a",
			}, nil),
			nil,
		},
		{
			"contractor location contains non-supported chars",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorLocation: "&.,:;- @+#/()!?\"'",
			}, nil),
			errLocationInvalid,
		},
		{
			"contractor location contains newline",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorLocation: "invoice location\n",
			}, nil),
			errLocationInvalid,
		},
		{
			"contractor location contains tab",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorLocation: "invoice location\t",
			}, nil),
			errLocationInvalid,
		},
		{
			"contractor location contains brackets",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorLocation: "{invoice location}",
			}, nil),
			errLocationInvalid,
		},
		{
			"contractor location is valid lowercase",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorLocation: "invoice location",
			}, nil),
			nil,
		},
		{
			"contractor location is valid mixed case",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorLocation: "Invoice Location",
			}, nil),
			nil,
		},
	}
}

// invoiceContactTests returns a list of tests that verify the invoice contact
// requirements.
func invoiceContactTests(t *testing.T) []invoiceFormatTest {
	t.Helper()

	// Create contacts to test min and max lengths
	var (
		contactTooShort  string
		contactTooLong   string
		contactMinLength string
		contactMaxLength string

		b strings.Builder
	)
	for i := 0; i < int(cms.SettingContactLengthMin)-1; i++ {
		b.WriteString("a")
	}
	contactTooShort = b.String()
	b.Reset()

	for i := 0; i < int(cms.SettingContactLengthMax)+1; i++ {
		b.WriteString("a")
	}
	contactTooLong = b.String()
	b.Reset()

	for i := 0; i < int(cms.SettingContactLengthMin); i++ {
		b.WriteString("a")
	}
	contactMinLength = b.String()
	b.Reset()

	for i := 0; i < int(cms.SettingContactLengthMax); i++ {
		b.WriteString("a")
	}
	contactMaxLength = b.String()

	// Setup files with an empty invoice contact. This is done manually
	// because the function that creates the invoice metadata uses
	// a default value when the contact is provided as an empty string.
	filesEmptyContact := filesForInvoice(t, &cms.InvoiceMetadata{
		ContractorContact: "",
	}, nil)
	for k, v := range filesEmptyContact {
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
			pm.ContractorContact = ""
			b, err = json.Marshal(pm)
			if err != nil {
				t.Fatal(err)
			}
			v.Payload = base64.StdEncoding.EncodeToString(b)
			filesEmptyContact[k] = v
		}
	}

	// errContactInvalid is returned when invoice contact validation
	// fails.
	errContactInvalid := backend.PluginError{
		PluginID:  cms.PluginID,
		ErrorCode: uint32(cms.ErrorStatusInvoiceMalformedContact),
	}
	// errContactMissing is returned when invoice contact is missing
	errContactMissing := backend.PluginError{
		PluginID:  cms.PluginID,
		ErrorCode: uint32(cms.ErrorStatusInvoiceMissingContact),
	}

	return []invoiceFormatTest{
		{
			"contractor contact is empty",
			filesEmptyContact,
			errContactMissing,
		},
		{
			"contractor contact is too short",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorContact: contactTooShort,
			}, nil),
			errContactInvalid,
		},
		{
			"contractor contact is too long",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorContact: contactTooLong,
			}, nil),
			errContactInvalid,
		},
		{
			"contractor contact is the min length",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorContact: contactMinLength,
			}, nil),
			nil,
		},
		{
			"contractor contact is the max length",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorContact: contactMaxLength,
			}, nil),
			nil,
		},
		{
			"contractor contact contains A to Z",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorContact: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
			}, nil),
			nil,
		},
		{
			"contractor contact contains a to z",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorContact: "abcdefghijklmnopqrstuvwxyz",
			}, nil),
			nil,
		},
		{
			"contractor contact contains 0 to 9",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorContact: "0123456789",
			}, nil),
			nil,
		},
		{
			"contractor contact contains supported chars",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorContact: ".a-b,a",
			}, nil),
			nil,
		},
		{
			"contractor contact contains non-supported chars",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorContact: "&.,:;- @+#/()!?\"'",
			}, nil),
			errContactInvalid,
		},
		{
			"contractor contact contains newline",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorContact: "invoice contact\n",
			}, nil),
			errContactInvalid,
		},
		{
			"contractor contact contains tab",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorContact: "invoice contact\t",
			}, nil),
			errContactInvalid,
		},
		{
			"contractor contact contains brackets",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorContact: "{invoice contact}",
			}, nil),
			errContactInvalid,
		},
		{
			"contractor contact is valid lowercase",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorContact: "invoice contact",
			}, nil),
			nil,
		},
		{
			"contractor contact is valid mixed case",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorContact: "Invoice Contact",
			}, nil),
			nil,
		},
	}
}

// invoiceRateTests returns a list of tests that verify the invoice rate
// requirements.
func invoiceRateTests(t *testing.T) []invoiceFormatTest {
	t.Helper()

	// Create names to test min and max lengths
	var (
		rateTooLow  uint32
		rateTooHigh uint32
		rateAverage uint32
	)
	rateTooLow = cms.SettingContractorRateMin - 1
	rateTooHigh = cms.SettingContractorRateMax + 1
	rateAverage = (cms.SettingContractorRateMax + cms.SettingContractorRateMin) / 2

	// Setup files with an empty invoice rate. This is done manually
	// because the function that creates the invoice metadata uses
	// a default value when the rate is provided as an empty string.
	filesEmptyRate := filesForInvoice(t, &cms.InvoiceMetadata{
		ContractorRate: 0,
	}, nil)
	for k, v := range filesEmptyRate {
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
			pm.ContractorRate = 0
			b, err = json.Marshal(pm)
			if err != nil {
				t.Fatal(err)
			}
			v.Payload = base64.StdEncoding.EncodeToString(b)
			filesEmptyRate[k] = v
		}
	}

	// errContractorRateInvalid is returned when invoice rate validation
	// fails.
	errContractorRateMissing := backend.PluginError{
		PluginID:  cms.PluginID,
		ErrorCode: uint32(cms.ErrorStatusInvoiceMissingRate),
	}
	// errContractorRateInvalid is returned when invoice rate validation
	// fails.
	errContractorRateInvalid := backend.PluginError{
		PluginID:  cms.PluginID,
		ErrorCode: uint32(cms.ErrorStatusInvoiceInvalidRate),
	}
	return []invoiceFormatTest{
		{
			"contractor rate is empty",
			filesEmptyRate,
			errContractorRateMissing,
		},
		{
			"contractor rate is too low",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorRate: uint(rateTooLow),
			}, nil),
			errContractorRateInvalid,
		},
		{
			"contractor rate is too high",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorRate: uint(rateTooHigh),
			}, nil),
			errContractorRateInvalid,
		},
		{
			"contractor rate is acceptable",
			filesForInvoice(t, &cms.InvoiceMetadata{
				ContractorRate: uint(rateAverage),
			}, nil),
			nil,
		},
	}
}

// invoicePaymentAddressTests returns a list of tests that verify the invoice
// payment address requirements.
func invoicePaymentAddressTests(t *testing.T) []invoiceFormatTest {
	t.Helper()

	var (
		addressWrongNetwork   string
		addressCorrectNetwork string
	)

	// MainNet Legacy Treasury Address
	addressWrongNetwork = "Dcur2mcGjmENx4DhNqDctW5wJCVyT3Qeqkx"
	// TestNet3 Legacy Treasury Address
	addressCorrectNetwork = "TcrypGAcGCRVXrES7hWqVZb5oLJKCZEtoL1"

	// Setup files with an empty invoice address. This is done manually
	// because the function that creates the invoice metadata uses
	// a default value when the address is provided as an empty string.
	filesEmptyAddress := filesForInvoice(t, &cms.InvoiceMetadata{
		PaymentAddress: "",
	}, nil)
	for k, v := range filesEmptyAddress {
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
			pm.PaymentAddress = ""
			b, err = json.Marshal(pm)
			if err != nil {
				t.Fatal(err)
			}
			v.Payload = base64.StdEncoding.EncodeToString(b)
			filesEmptyAddress[k] = v
		}
	}

	// errPaymentAddressInvalid is returned when invoice address is missing
	errPaymentAddressMissing := backend.PluginError{
		PluginID:  cms.PluginID,
		ErrorCode: uint32(cms.ErrorStatusMissingPaymentAddress),
	}
	// errPaymentAddressInvalid is returned when invoice address validation
	// fails.
	errPaymentAddressInvalid := backend.PluginError{
		PluginID:  cms.PluginID,
		ErrorCode: uint32(cms.ErrorStatusInvalidPaymentAddress),
	}
	return []invoiceFormatTest{
		{
			"payment address is empty",
			filesEmptyAddress,
			errPaymentAddressMissing,
		},
		{
			"payment address is invalid",
			filesForInvoice(t, &cms.InvoiceMetadata{
				PaymentAddress: "INVALID ADDRESS",
			}, nil),
			errPaymentAddressInvalid,
		},
		{
			"payment address is wrong network",
			filesForInvoice(t, &cms.InvoiceMetadata{
				PaymentAddress: addressWrongNetwork,
			}, nil),
			errPaymentAddressInvalid,
		},
		{
			"paytment address is acceptable",
			filesForInvoice(t, &cms.InvoiceMetadata{
				PaymentAddress: addressCorrectNetwork,
			}, nil),
			nil,
		},
	}
}

// invoiceMonthYearTests returns a list of tests that verify the invoice
// month/year requirements.
func invoiceMonthYearTests(t *testing.T) []invoiceFormatTest {
	t.Helper()

	var (
		monthTooHigh uint
		monthTooSoon uint
		yearTooSoon  uint
	)

	// Setup files with an empty invoice month. This is done manually
	// because the function that creates the invoice metadata uses
	// a default value when the month is provided as an empty value.
	filesEmptyMonth := filesForInvoice(t, &cms.InvoiceMetadata{
		PaymentAddress: "",
	}, nil)
	for k, v := range filesEmptyMonth {
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
			pm.Month = 0
			b, err = json.Marshal(pm)
			if err != nil {
				t.Fatal(err)
			}
			v.Payload = base64.StdEncoding.EncodeToString(b)
			filesEmptyMonth[k] = v
		}
	}
	monthTooHigh = 13

	// Calculate the month/year for a future month based on the current date.
	futureMonth := int(time.Now().Month()) + 2
	futureMonthDate := time.Date(time.Now().Year(), time.Month(futureMonth),
		1, 0, 0, 0, 0, time.Local)
	monthTooSoon = uint(futureMonthDate.Month())
	yearTooSoon = uint(futureMonthDate.Year())

	// errMonthYearInvalid is returned when invoice month/year validation
	// fails.
	errMonthYearInvalid := backend.PluginError{
		PluginID:  cms.PluginID,
		ErrorCode: uint32(cms.ErrorStatusInvalidInvoiceMonthYear),
	}
	return []invoiceFormatTest{
		{
			"month is too low",
			filesEmptyMonth,
			errMonthYearInvalid,
		},
		{
			"month is too high",
			filesForInvoice(t, &cms.InvoiceMetadata{
				Month: monthTooHigh,
				Year:  2020,
			}, nil),
			errMonthYearInvalid,
		},
		{
			"month is too soon",
			filesForInvoice(t, &cms.InvoiceMetadata{
				Month: monthTooSoon,
				Year:  yearTooSoon,
			}, nil),
			errMonthYearInvalid,
		},
		{
			"month is acceptable",
			filesForInvoice(t, &cms.InvoiceMetadata{
				Month: 10,
				Year:  2020,
			}, nil),
			nil,
		},
	}
}

// invoiceExchangeTests returns a list of tests that verify the invoice
// exchange requirements.
func invoiceExchangeRateTests(t *testing.T) []invoiceFormatTest {
	t.Helper()
	// XXX Still need to figure out what we're doing here to verify
	// exchange rate due to movement of the exchange rate db table
	return []invoiceFormatTest{}
}

// lineItemTests returns a list of tests that verify the line items
// requirements.
func lineItemTests(t *testing.T) []invoiceFormatTest {
	t.Helper()

	// Setup test files

	var (
		subdomainTooShort  string
		subdomainTooLong   string
		subdomainMinLength string
		subdomainMaxLength string

		descriptionTooShort  string
		descriptionTooLong   string
		descriptionMinLength string
		descriptionMaxLength string

		proposalTokenTooShort  string
		proposalTokenTooLong   string
		proposalTokenMinLength string
		proposalTokenMaxLength string

		invoiceMetaData = fileInvoiceMetadata(t, nil)
		indexBadParse   backend.File
		indexEmpty      backend.File

		sb strings.Builder
	)

	// Create various subdomain strings
	for i := 0; i < int(cms.SettingLineItemColLengthMin)-1; i++ {
		sb.WriteString("a")
	}
	subdomainTooShort = sb.String()
	sb.Reset()

	for i := 0; i < int(cms.SettingLineItemColLengthMax)+1; i++ {
		sb.WriteString("a")
	}
	subdomainTooLong = sb.String()
	sb.Reset()

	for i := 0; i < int(cms.SettingLineItemColLengthMin); i++ {
		sb.WriteString("a")
	}
	subdomainMinLength = sb.String()
	sb.Reset()

	for i := 0; i < int(cms.SettingLineItemColLengthMax); i++ {
		sb.WriteString("a")
	}
	subdomainMaxLength = sb.String()
	sb.Reset()

	// Create various description strings
	for i := 0; i < int(cms.SettingLineItemColLengthMin)-1; i++ {
		sb.WriteString("a")
	}
	descriptionTooShort = sb.String()
	sb.Reset()

	for i := 0; i < int(cms.SettingLineItemColLengthMax)+1; i++ {
		sb.WriteString("a")
	}
	descriptionTooLong = sb.String()
	sb.Reset()

	for i := 0; i < int(cms.SettingLineItemColLengthMin); i++ {
		sb.WriteString("a")
	}
	descriptionMinLength = sb.String()
	sb.Reset()

	for i := 0; i < int(cms.SettingLineItemColLengthMax); i++ {
		sb.WriteString("a")
	}
	descriptionMaxLength = sb.String()
	sb.Reset()

	for i := 0; i < int(cms.SettingLineItemColLengthMin)-1; i++ {
		sb.WriteString("a")
	}

	// Create various proposal strings
	proposalTokenTooShort = sb.String()
	sb.Reset()

	for i := 0; i < int(cms.SettingLineItemColLengthMax)+1; i++ {
		sb.WriteString("a")
	}
	proposalTokenTooLong = sb.String()
	sb.Reset()

	for i := 0; i < int(cms.SettingLineItemColLengthMin); i++ {
		sb.WriteString("a")
	}
	proposalTokenMinLength = sb.String()
	sb.Reset()

	for i := 0; i < int(cms.SettingLineItemColLengthMax); i++ {
		sb.WriteString("a")
	}
	proposalTokenMaxLength = sb.String()
	sb.Reset()

	// Create an index file that can't be parsed
	for i := 0; i <= int(cms.SettingTextFileSizeMax)-1; i++ {
		sb.WriteString("a")
	}
	indexBadParse = file(cms.FileNameIndexFile, []byte(sb.String()))
	sb.Reset()

	// Create an index file that is empty
	emptyInvoice := cms.InvoiceInput{}

	b, err := json.Marshal(emptyInvoice)
	if err != nil {
		t.Fatal(err)
	}
	indexEmpty = file(cms.FileNameIndexFile, b)

	// errInvalidIndexFile is returned when an invalid index file is given
	errInvalidIndexFile := backend.PluginError{
		PluginID:  cms.PluginID,
		ErrorCode: uint32(cms.ErrorStatusMalformedInvoiceFile),
	}
	// errRequireLineItems is returned when an empty index file is given
	errRequireLineItems := backend.PluginError{
		PluginID:  cms.PluginID,
		ErrorCode: uint32(cms.ErrorStatusInvoiceRequireLineItems),
	}
	// errInvalidDomain is returned when an invalid domain is given
	errInvalidDomain := backend.PluginError{
		PluginID:  cms.PluginID,
		ErrorCode: uint32(cms.ErrorCodeInvoiceDomainInvalid),
	}
	// errInvalidDomain is returned when an invalid domain is given
	errInvalidSubdomain := backend.PluginError{
		PluginID:  cms.PluginID,
		ErrorCode: uint32(cms.ErrorStatusMalformedSubdomain),
	}

	return []invoiceFormatTest{
		{
			"can't parse invoice input",
			[]backend.File{
				indexBadParse,
				invoiceMetaData,
			},
			errInvalidIndexFile,
		},
		{
			"must have at least 1 line item",
			[]backend.File{
				indexEmpty,
				invoiceMetaData,
			},
			errRequireLineItems,
		},
		{
			"invalid domain",
			[]backend.File{
				fileInvoiceIndex(t, &cms.LineItemsInput{
					Domain: "baddomain",
				}),
				invoiceMetaData,
			},
			errInvalidDomain,
		},
		{
			"valid domain",
			[]backend.File{
				fileInvoiceIndex(t, &cms.LineItemsInput{
					Domain: "development",
				}),
				invoiceMetaData,
			},
			nil,
		},
		{
			"invalid subdomain too short",
			[]backend.File{
				fileInvoiceIndex(t, &cms.LineItemsInput{
					Subdomain: subdomainTooShort,
				}),
				invoiceMetaData,
			},
			errInvalidSubdomain,
		},
		{
			"invalid subdomain too long",
			[]backend.File{
				fileInvoiceIndex(t, &cms.LineItemsInput{
					Subdomain: subdomainTooLong,
				}),
				invoiceMetaData,
			},
			errInvalidSubdomain,
		},
		{
			"valid subdomain at min",
			[]backend.File{
				fileInvoiceIndex(t, &cms.LineItemsInput{
					Subdomain: subdomainMinLength,
				}),
				invoiceMetaData,
			},
			nil,
		},
		{
			"valid subdomain at max",
			[]backend.File{
				fileInvoiceIndex(t, &cms.LineItemsInput{
					Subdomain: subdomainMaxLength,
				}),
				invoiceMetaData,
			},
			nil,
		},
		{
			"invalid description too short",
			[]backend.File{
				fileInvoiceIndex(t, &cms.LineItemsInput{
					Subdomain: descriptionTooShort,
				}),
				invoiceMetaData,
			},
			errInvalidSubdomain,
		},
		{
			"invalid description too long",
			[]backend.File{
				fileInvoiceIndex(t, &cms.LineItemsInput{
					Subdomain: descriptionTooLong,
				}),
				invoiceMetaData,
			},
			errInvalidSubdomain,
		},
		{
			"valid description at min",
			[]backend.File{
				fileInvoiceIndex(t, &cms.LineItemsInput{
					Subdomain: descriptionMinLength,
				}),
				invoiceMetaData,
			},
			nil,
		},
		{
			"valid description at max",
			[]backend.File{
				fileInvoiceIndex(t, &cms.LineItemsInput{
					Subdomain: descriptionMaxLength,
				}),
				invoiceMetaData,
			},
			nil,
		},
		{
			"invalid proptoken too short",
			[]backend.File{
				fileInvoiceIndex(t, &cms.LineItemsInput{
					Subdomain: proposalTokenTooShort,
				}),
				invoiceMetaData,
			},
			errInvalidSubdomain,
		},
		{
			"invalid proptoken too long",
			[]backend.File{
				fileInvoiceIndex(t, &cms.LineItemsInput{
					Subdomain: proposalTokenTooLong,
				}),
				invoiceMetaData,
			},
			errInvalidSubdomain,
		},
		{
			"valid proptoken at min",
			[]backend.File{
				fileInvoiceIndex(t, &cms.LineItemsInput{
					Subdomain: proposalTokenMinLength,
				}),
				invoiceMetaData,
			},
			nil,
		},
		{
			"valid proptoken at max",
			[]backend.File{
				fileInvoiceIndex(t, &cms.LineItemsInput{
					Subdomain: proposalTokenMaxLength,
				}),
				invoiceMetaData,
			},
			nil,
		},
		// ErrorStatusMalformedSubdomain
		// ErrorStatusMalformedDescription
		// ErrorStatusMalformedProposalToken
		// If labor type:
		//   labor field is zero: ErrorStatusInvalidLaborExpense
		//   expense field is non-zero: ErrorStatusInvalidLaborExpense
		//   sub-rate field is non-zero: ErrorStatusInvoiceInvalidRate
		//   sub-userid field is not empty: ErrorStatusInvalidSubUserIDLineItem
		// If Expense of Misc:
		//	 labor field is non-zero: ErrorStatusInvalidLaborExpense
		// If Sub Hours:
		//   labor field is zero: ErrorStatusInvalidLaborExpense
		// 	 sub-rate is too high: ErrorStatusInvoiceInvalidRate
		//   sub-rate is too low: ErrorStatusInvoiceInvalidRate
		// ErrorStatusInvalidLineItemType
	}
}

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
func fileInvoiceIndex(t *testing.T, li *cms.LineItemsInput) backend.File {

	testInvoice := cms.InvoiceInput{}

	testLineItems := []cms.LineItemsInput{
		{
			Type:          cms.LineItemTypeLabor,
			Domain:        "development",
			Subdomain:     "sub-domain stuff",
			Description:   "this is the first line description.",
			ProposalToken: "6db3c4e9092bb94a",
			SubUserID:     "",
			SubRate:       0,
			Labor:         1000,
			Expenses:      0,
		},
		{
			Type:          cms.LineItemTypeExpense,
			Domain:        "development",
			Subdomain:     "sub",
			Description:   "this is the second line description.",
			ProposalToken: "6db3c4e9092bb94a",
			SubUserID:     "",
			SubRate:       0,
			Labor:         0,
			Expenses:      1000,
		},
		{
			Type:          cms.LineItemTypeSubHours,
			Domain:        "development",
			Subdomain:     "sub",
			Description:   "this is the third line description.",
			ProposalToken: "6db3c4e9092bb94a",
			SubUserID:     "ff7f5740-6440-4b7e-8de4-f76a9cb6d98f",
			SubRate:       1000,
			Labor:         1000,
			Expenses:      0,
		}}
	// Overwrite the default values with the caller provided
	// values if they exist.
	if li == nil {
		li = &cms.LineItemsInput{}
	}
	// Use labor line item as default
	var editIndex = 0
	switch li.Type {
	case cms.LineItemTypeExpense, cms.LineItemTypeMisc:
		editIndex = 1
	case cms.LineItemTypeSubHours:
		editIndex = 2
	}

	if li.Domain != "" {
		testLineItems[editIndex].Domain = li.Domain
	}
	if li.Subdomain != "" {
		testLineItems[editIndex].Subdomain = li.Subdomain
	}
	if li.Description != "" {
		testLineItems[editIndex].Description = li.Description
	}
	if li.ProposalToken != "" {
		testLineItems[editIndex].ProposalToken = li.ProposalToken
	}
	if li.SubUserID != "" {
		testLineItems[editIndex].SubUserID = li.SubUserID
	}
	if li.SubRate != 0 {
		testLineItems[editIndex].SubRate = li.SubRate
	}
	if li.Labor != 0 {
		testLineItems[editIndex].Labor = li.Labor
	}
	if li.Expenses != 0 {
		testLineItems[editIndex].Expenses = li.Expenses
	}

	testInvoice.LineItems = testLineItems

	// Create a raw json []byte from the above information
	b, err := json.Marshal(testInvoice)
	if err != nil {
		t.Fatal(err)
	}
	return file(cms.FileNameIndexFile, b)
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
		Month:              3,
		Year:               2021,
		ExchangeRate:       10000,
		ContractorName:     "Test McTesterson",
		ContractorLocation: "TestVille, USA",
		ContractorContact:  "test@decred.org",
		ContractorRate:     5000,
		PaymentAddress:     "TskbfyX1zjCwMJuYJgzqc9msC9R66ScmWti",
	}

	// Overwrite the default values with the caller provided
	// values if they exist.
	if pm == nil {
		pm = &cms.InvoiceMetadata{}
	}
	if pm.Month != 0 {
		pmd.Month = pm.Month
	}
	if pm.Year != 0 {
		pmd.Year = pm.Year
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
func filesForInvoice(t *testing.T, pm *cms.InvoiceMetadata, li *cms.LineItemsInput, files ...backend.File) []backend.File {
	t.Helper()
	fs := []backend.File{
		fileInvoiceIndex(t, li),
		fileInvoiceMetadata(t, pm),
	}
	fs = append(fs, files...)

	return fs
}
