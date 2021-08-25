// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

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
	"github.com/decred/politeia/politeiad/plugins/comments"
	"github.com/decred/politeia/politeiad/plugins/pi"
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
	// Setup pi plugin
	p, cleanup := newTestPiPlugin(t)
	defer cleanup()

	// Run tests
	runProposalFormatTests(t, p.hookNewRecordPre)
}

func TestHookEditRecordPre(t *testing.T) {
	// Setup pi plugin
	p, cleanup := newTestPiPlugin(t)
	defer cleanup()

	// Run tests
	runProposalFormatTests(t, p.hookEditRecordPre)
}

// runProposalFormatTests runs the proposal format tests using the provided
// hook function as the test function. This allows us to run the same set of
// formatting tests of multiple hooks without needing to duplicate the setup
// and error handling code.
func runProposalFormatTests(t *testing.T, hookFn func(string) error) {
	for _, v := range proposalFormatTests(t) {
		t.Run(v.name, func(t *testing.T) {
			// Decode the expected error into a PluginError. If
			// an error is being returned it should always be a
			// PluginError.
			var wantErrorCode pi.ErrorCodeT
			if v.err != nil {
				var pe backend.PluginError
				if !errors.As(v.err, &pe) {
					t.Fatalf("error is not a plugin error '%v'", v.err)
				}
				wantErrorCode = pi.ErrorCodeT(pe.ErrorCode)
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
					pi.ErrorCodes[wantErrorCode])
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
				if pi.PluginID != gotErr.PluginID {
					t.Errorf("want plugin error with plugin ID '%v', got '%v'",
						pi.PluginID, gotErr.PluginID)
					return
				}

				gotErrorCode := pi.ErrorCodeT(gotErr.ErrorCode)
				if wantErrorCode != gotErrorCode {
					t.Errorf("want error '%v', got '%v'",
						pi.ErrorCodes[wantErrorCode],
						pi.ErrorCodes[gotErrorCode])
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

// proposalFormatTest contains the input and output for a test that verifies
// the proposal format meets the pi plugin requirements.
type proposalFormatTest struct {
	name  string         // Test name
	files []backend.File // Input
	err   error          // Expected output
}

// proposalFormatTests returns a list of tests that verify the files of a
// proposal meet all formatting criteria that the pi plugin requires.
func proposalFormatTests(t *testing.T) []proposalFormatTest {
	t.Helper()

	// Setup test files
	var (
		index = fileProposalIndex()

		indexTooLarge backend.File
		png           backend.File
		pngTooLarge   backend.File
	)

	// Create a index file that is too large
	var sb strings.Builder
	for i := 0; i <= int(pi.SettingTextFileSizeMax); i++ {
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
	tests := []proposalFormatTest{
		{
			"text file name invalid",
			[]backend.File{
				{
					Name:    "notallowed.txt",
					MIME:    index.MIME,
					Digest:  index.Digest,
					Payload: index.Payload,
				},
				fileProposalMetadata(t, nil),
			},
			backend.PluginError{
				PluginID:  pi.PluginID,
				ErrorCode: uint32(pi.ErrorCodeTextFileNameInvalid),
			},
		},
		{
			"text file too large",
			[]backend.File{
				indexTooLarge,
				fileProposalMetadata(t, nil),
			},
			backend.PluginError{
				PluginID:  pi.PluginID,
				ErrorCode: uint32(pi.ErrorCodeTextFileSizeInvalid),
			},
		},
		{
			"image file too large",
			[]backend.File{
				fileProposalIndex(),
				fileProposalMetadata(t, nil),
				pngTooLarge,
			},
			backend.PluginError{
				PluginID:  pi.PluginID,
				ErrorCode: uint32(pi.ErrorCodeImageFileSizeInvalid),
			},
		},
		{
			"index file missing",
			[]backend.File{
				fileProposalMetadata(t, nil),
			},
			backend.PluginError{
				PluginID:  pi.PluginID,
				ErrorCode: uint32(pi.ErrorCodeTextFileMissing),
			},
		},
		{
			"too many images",
			[]backend.File{
				fileProposalIndex(),
				fileProposalMetadata(t, nil),
				fileEmptyPNG(t), fileEmptyPNG(t), fileEmptyPNG(t),
				fileEmptyPNG(t), fileEmptyPNG(t), fileEmptyPNG(t),
			},
			backend.PluginError{
				PluginID:  pi.PluginID,
				ErrorCode: uint32(pi.ErrorCodeImageFileCountInvalid),
			},
		},
		{
			"proposal metadata missing",
			[]backend.File{
				fileProposalIndex(),
			},
			backend.PluginError{
				PluginID:  pi.PluginID,
				ErrorCode: uint32(pi.ErrorCodeTextFileMissing),
			},
		},
		{
			"success no attachments",
			[]backend.File{
				fileProposalIndex(),
				fileProposalMetadata(t, nil),
			},
			nil,
		},
		{
			"success with attachments",
			[]backend.File{
				fileProposalIndex(),
				fileProposalMetadata(t, nil),
				png,
			},
			nil,
		},
	}

	tests = append(tests, proposalNameTests(t)...)
	tests = append(tests, proposalAmountTests(t)...)
	tests = append(tests, proposalStartDateTests(t)...)
	tests = append(tests, proposalEndDateTests(t)...)
	tests = append(tests, proposalDomainTests(t)...)
	return tests
}

// proposalNameTests returns a list of tests that verify the proposal name
// requirements.
func proposalNameTests(t *testing.T) []proposalFormatTest {
	t.Helper()

	// Create names to test min and max lengths
	var (
		nameTooShort  string
		nameTooLong   string
		nameMinLength string
		nameMaxLength string

		b strings.Builder
	)
	for i := 0; i < int(pi.SettingTitleLengthMin)-1; i++ {
		b.WriteString("a")
	}
	nameTooShort = b.String()
	b.Reset()

	for i := 0; i < int(pi.SettingTitleLengthMax)+1; i++ {
		b.WriteString("a")
	}
	nameTooLong = b.String()
	b.Reset()

	for i := 0; i < int(pi.SettingTitleLengthMin); i++ {
		b.WriteString("a")
	}
	nameMinLength = b.String()
	b.Reset()

	for i := 0; i < int(pi.SettingTitleLengthMax); i++ {
		b.WriteString("a")
	}
	nameMaxLength = b.String()

	// Setup files with an empty proposal name. This is done manually
	// because the function that creates the proposal metadata uses
	// a default value when the name is provided as an empty string.
	filesEmptyName := filesForProposal(t, &pi.ProposalMetadata{
		Name: "",
	})
	for k, v := range filesEmptyName {
		if v.Name == pi.FileNameProposalMetadata {
			b, err := base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				t.Fatal(err)
			}
			var pm pi.ProposalMetadata
			err = json.Unmarshal(b, &pm)
			if err != nil {
				t.Fatal(err)
			}
			pm.Name = ""
			b, err = json.Marshal(pm)
			if err != nil {
				t.Fatal(err)
			}
			v.Payload = base64.StdEncoding.EncodeToString(b)
			filesEmptyName[k] = v
		}
	}

	// errNameInvalid is returned when proposal name validation
	// fails.
	errNameInvalid := backend.PluginError{
		PluginID:  pi.PluginID,
		ErrorCode: uint32(pi.ErrorCodeTitleInvalid),
	}

	return []proposalFormatTest{
		{
			"name is empty",
			filesEmptyName,
			errNameInvalid,
		},
		{
			"name is too short",
			filesForProposal(t, &pi.ProposalMetadata{
				Name: nameTooShort,
			}),
			errNameInvalid,
		},
		{
			"name is too long",
			filesForProposal(t, &pi.ProposalMetadata{
				Name: nameTooLong,
			}),
			errNameInvalid,
		},
		{
			"name is the min length",
			filesForProposal(t, &pi.ProposalMetadata{
				Name: nameMinLength,
			}),
			nil,
		},
		{
			"name is the max length",
			filesForProposal(t, &pi.ProposalMetadata{
				Name: nameMaxLength,
			}),
			nil,
		},
		{
			"name contains A to Z",
			filesForProposal(t, &pi.ProposalMetadata{
				Name: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
			}),
			nil,
		},
		{
			"name contains a to z",
			filesForProposal(t, &pi.ProposalMetadata{
				Name: "abcdefghijklmnopqrstuvwxyz",
			}),
			nil,
		},
		{
			"name contains 0 to 9",
			filesForProposal(t, &pi.ProposalMetadata{
				Name: "0123456789",
			}),
			nil,
		},
		{
			"name contains supported chars",
			filesForProposal(t, &pi.ProposalMetadata{
				Name: "&.,:;- @+#/()!?\"'",
			}),
			nil,
		},
		{
			"name contains newline",
			filesForProposal(t, &pi.ProposalMetadata{
				Name: "proposal name\n",
			}),
			errNameInvalid,
		},
		{
			"name contains tab",
			filesForProposal(t, &pi.ProposalMetadata{
				Name: "proposal name\t",
			}),
			errNameInvalid,
		},
		{
			"name contains brackets",
			filesForProposal(t, &pi.ProposalMetadata{
				Name: "{proposal name}",
			}),
			errNameInvalid,
		},
		{
			"name is valid lowercase",
			filesForProposal(t, &pi.ProposalMetadata{
				Name: "proposal name",
			}),
			nil,
		},
		{
			"name is valid mixed case",
			filesForProposal(t, &pi.ProposalMetadata{
				Name: "Proposal Name",
			}),
			nil,
		},
	}
}

// proposalAmountTests returns a list of tests that verify the proposal
// amount requirements.
func proposalAmountTests(t *testing.T) []proposalFormatTest {
	t.Helper()

	// amount values to test min & max amount limits
	var (
		amountMin      = pi.SettingProposalAmountMin
		amountMax      = pi.SettingProposalAmountMax
		amountTooSmall = amountMin - 1
		amountTooBig   = amountMax + 1
	)

	// Setup files with a zero amount. This is done manually
	// because the function that creates the proposal metadata uses
	// a default value when the amount is provided as zero.
	filesZeroAmount := filesForProposal(t, &pi.ProposalMetadata{
		Amount: 0,
	})
	for k, v := range filesZeroAmount {
		if v.Name == pi.FileNameProposalMetadata {
			b, err := base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				t.Fatal(err)
			}
			var pm pi.ProposalMetadata
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

	// errAmountInvalid is returned when proposal amount
	// validation fails.
	errAmountInvalid := backend.PluginError{
		PluginID:  pi.PluginID,
		ErrorCode: uint32(pi.ErrorCodeProposalAmountInvalid),
	}

	return []proposalFormatTest{
		{
			"amount is zero",
			filesZeroAmount,
			errAmountInvalid,
		},
		{
			"amount too small",
			filesForProposal(t, &pi.ProposalMetadata{
				Amount: amountTooSmall,
			}),
			errAmountInvalid,
		},
		{
			"amount too big",
			filesForProposal(t, &pi.ProposalMetadata{
				Amount: amountTooBig,
			}),
			errAmountInvalid,
		},
		{
			"min amount",
			filesForProposal(t, &pi.ProposalMetadata{
				Amount: amountMin,
			}),
			nil,
		},
		{
			"max amount",
			filesForProposal(t, &pi.ProposalMetadata{
				Amount: amountMax,
			}),
			nil,
		},
	}
}

// proposalStartDateTests returns a list of tests that verify the proposal
// start date requirements.
func proposalStartDateTests(t *testing.T) []proposalFormatTest {
	t.Helper()

	// Start date values to test min start date
	var (
		sDateInPast      = time.Now().Unix() - 172800  // two days ago
		sDateInTwoMonths = time.Now().Unix() + 5256000 // in 2 months
	)

	// Setup files with a zero start date. This is done manually
	// because the function that creates the proposal metadata uses
	// a default value when the start date is provided as zero.
	filesZeroStartDate := filesForProposal(t, &pi.ProposalMetadata{
		StartDate: 0,
	})
	for k, v := range filesZeroStartDate {
		if v.Name == pi.FileNameProposalMetadata {
			b, err := base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				t.Fatal(err)
			}
			var pm pi.ProposalMetadata
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

	// errStartDateInvalid is returned when proposal start date
	// validation fails.
	errStartDateInvalid := backend.PluginError{
		PluginID:  pi.PluginID,
		ErrorCode: uint32(pi.ErrorCodeProposalStartDateInvalid),
	}

	return []proposalFormatTest{
		{
			"start date in the past",
			filesForProposal(t, &pi.ProposalMetadata{
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
			filesForProposal(t, &pi.ProposalMetadata{
				StartDate: sDateInTwoMonths,
			}),
			nil,
		},
	}
}

// proposalEndDateTests returns a list of tests that verify the proposal
// end date requirements.
func proposalEndDateTests(t *testing.T) []proposalFormatTest {
	t.Helper()

	// End date values to test end date validations.
	var (
		now                  = time.Now().Unix()
		eDateInPast          = now - 172800 // two days ago
		eDateBeforeStartDate = now + 172800 // in two days
		eDateAfterMax        = now +
			pi.SettingProposalEndDateMax + 60 // 1 minute after max
		eDateInEightMonths = now + 21040000 // in 8 months
	)

	// Setup files with a zero end date. This is done manually
	// because the function that creates the proposal metadata uses
	// a default value when the end date is provided as zero.
	filesZeroEndDate := filesForProposal(t, &pi.ProposalMetadata{
		EndDate: 0,
	})
	for k, v := range filesZeroEndDate {
		if v.Name == pi.FileNameProposalMetadata {
			b, err := base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				t.Fatal(err)
			}
			var pm pi.ProposalMetadata
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

	// errEndDateInvalid is returned when proposal end date
	// validation fails.
	errEndDateInvalid := backend.PluginError{
		PluginID:  pi.PluginID,
		ErrorCode: uint32(pi.ErrorCodeProposalEndDateInvalid),
	}

	return []proposalFormatTest{
		{
			"end date in the past",
			filesForProposal(t, &pi.ProposalMetadata{
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
			filesForProposal(t, &pi.ProposalMetadata{
				EndDate: eDateBeforeStartDate,
			}),
			errEndDateInvalid,
		},
		{
			"end date is after max",
			filesForProposal(t, &pi.ProposalMetadata{
				EndDate: eDateAfterMax,
			}),
			errEndDateInvalid,
		},
		{
			"end date is in 8 months",
			filesForProposal(t, &pi.ProposalMetadata{
				EndDate: eDateInEightMonths,
			}),
			nil,
		},
	}
}

// proposalDomainTests returns a list of tests that verify the proposal
// domain requirements.
func proposalDomainTests(t *testing.T) []proposalFormatTest {
	t.Helper()

	// Domain values to test domain validations.
	var (
		validDomain   = pi.SettingProposalDomains[0]
		invalidDomain = "invalid-domain"
	)

	// Setup files with an empty domain. This is done manually
	// because the function that creates the proposal metadata uses
	// a default value when the domain is provided as empty string.
	filesEmptyDomain := filesForProposal(t, &pi.ProposalMetadata{
		Domain: "",
	})
	for k, v := range filesEmptyDomain {
		if v.Name == pi.FileNameProposalMetadata {
			b, err := base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				t.Fatal(err)
			}
			var pm pi.ProposalMetadata
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

	// errDomainInvalid is returned when proposal domain
	// validation fails.
	errDomainInvalid := backend.PluginError{
		PluginID:  pi.PluginID,
		ErrorCode: uint32(pi.ErrorCodeProposalDomainInvalid),
	}

	return []proposalFormatTest{
		{
			"invalid domain",
			filesForProposal(t, &pi.ProposalMetadata{
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
			filesForProposal(t, &pi.ProposalMetadata{
				Domain: validDomain,
			}),
			nil,
		},
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

// fileProposalIndex returns a backend file that contains a proposal index
// file.
func fileProposalIndex() backend.File {
	text := "Hello, world. This is my proposal. Pay me."
	return file(pi.FileNameIndexFile, []byte(text))
}

// fileProposalMetadata returns a backend file that contains a proposal
// metadata file. The proposal metadata can optionally be provided as an
// argument. Any required proposal metadata fields that are not provided by
// the caller will be filled in using valid defaults.
func fileProposalMetadata(t *testing.T, pm *pi.ProposalMetadata) backend.File {
	t.Helper()

	// Setup a default proposal metadata
	pmd := &pi.ProposalMetadata{
		Name:      "Test Proposal Name",
		Amount:    2000000,                      // $20k in cents
		StartDate: time.Now().Unix() + 2630000,  // 1 month from now
		EndDate:   time.Now().Unix() + 10368000, // 4 months from now
		Domain:    "development",
	}

	// Sanity check. Verify that the default domain we used is
	// one of the default domains defined by the pi plugin API.
	var found bool
	for _, v := range pi.SettingProposalDomains {
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
		pm = &pi.ProposalMetadata{}
	}
	if pm.Name != "" {
		pmd.Name = pm.Name
	}
	if pm.Amount != 0 {
		pmd.Amount = pm.Amount
	}
	if pm.StartDate != 0 {
		pmd.StartDate = pm.StartDate
	}
	if pm.EndDate != 0 {
		pmd.EndDate = pm.EndDate
	}
	if pm.Domain != "" {
		pmd.Domain = pm.Domain
	}

	// Setup and return the backend file
	b, err := json.Marshal(&pmd)
	if err != nil {
		t.Fatal(err)
	}

	return file(pi.FileNameProposalMetadata, b)
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

// filesForProposal returns the backend files for a valid proposal. The
// returned files only include the files required by the pi plugin API. No
// attachment files are included. The caller can pass in additional files that
// will be included in the returned list.
func filesForProposal(t *testing.T, pm *pi.ProposalMetadata, files ...backend.File) []backend.File {
	t.Helper()

	fs := []backend.File{
		fileProposalIndex(),
		fileProposalMetadata(t, pm),
	}
	fs = append(fs, files...)

	return fs
}
