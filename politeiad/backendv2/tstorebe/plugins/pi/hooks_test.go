// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/decred/politeia/util"
)

func TestHookNewRecordPre(t *testing.T) {
	// Setup pi plugin
	p, cleanup := newTestPiPlugin(t)
	defer cleanup()

	// Run tests
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
			err = p.hookNewRecordPre(payload)
			switch {
			case v.err != nil && err == nil:
				// Wanted an error but didn't get one
				t.Errorf("want error '%v', got nil",
					pi.ErrorCodes[wantErrorCode])

			case v.err == nil && err != nil:
				// Wanted success but got an error
				t.Errorf("want error nil, got '%v'", err)

			case v.err != nil && err != nil:
				// Wanted an error and got an error. Verify
				// that it's the correct error.
				var gotErr backend.PluginError
				if !errors.As(v.err, &gotErr) {
					t.Errorf("want error '%v', got '%v'",
						pi.ErrorCodes[wantErrorCode], v.err)
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
	tests := []proposalFormatTest{
		{
			"text file name invalid",
			filesForProposal(t,
				backend.File{
					Name: "notallowed.txt",
				}),
			backend.PluginError{
				PluginID:  pi.PluginID,
				ErrorCode: uint32(pi.ErrorCodeTextFileNameInvalid),
			},
		},
		{
			"text file size invalid",
			[]backend.File{},
			// pi.ErrorCodeTextFileSizeInvalid,
			nil,
		},
		{
			"image file size invalid",
			[]backend.File{},
			// pi.ErrorCodeImageFileSizeInvalid,
			nil,
		},
		{
			"index file missing",
			[]backend.File{},
			// pi.ErrorCodeTextFileMissing,
			nil,
		},
		{
			"too many images",
			[]backend.File{},
			// pi.ErrorCodeImageFileCountInvalid,
			nil,
		},
		{
			"proposal metadata missing",
			[]backend.File{},
			// pi.ErrorCodeTextFileMissing,
			nil,
		},
	}

	tests = append(tests, proposalNameTests(t)...)
	return tests
}

// proposalNameTests returns a list of tests that verify the proposal name
// requirements.
func proposalNameTests(t *testing.T) []proposalFormatTest {
	// Create names to test min and max lengths
	var (
		nameTooShort  string
		nameTooLong   string
		nameMinLength string
		nameMaxLength string

		b strings.Builder
	)
	for i := 0; i < int(pi.SettingProposalNameLengthMin)-1; i++ {
		b.WriteString("a")
	}
	nameTooShort = b.String()
	b.Reset()

	for i := 0; i < int(pi.SettingProposalNameLengthMax)+1; i++ {
		b.WriteString("a")
	}
	nameTooLong = b.String()
	b.Reset()

	for i := 0; i < int(pi.SettingProposalNameLengthMin); i++ {
		b.WriteString("a")
	}
	nameMinLength = b.String()
	b.Reset()

	for i := 0; i < int(pi.SettingProposalNameLengthMax); i++ {
		b.WriteString("a")
	}
	nameMaxLength = b.String()

	// errNameInvalid is returned when proposal name validation
	// fails.
	errNameInvalid := backend.PluginError{
		PluginID:  pi.PluginID,
		ErrorCode: uint32(pi.ErrorCodeProposalNameInvalid),
	}

	return []proposalFormatTest{
		{
			"name is empty",
			filesWithProposalName(t, ""),
			errNameInvalid,
		},
		{
			"name is too short",
			filesWithProposalName(t, nameTooShort),
			errNameInvalid,
		},
		{
			"name is too long",
			filesWithProposalName(t, nameTooLong),
			errNameInvalid,
		},
		{
			"name is the min length",
			filesWithProposalName(t, nameMinLength),
			nil,
		},
		{
			"name is the max length",
			filesWithProposalName(t, nameMaxLength),
			nil,
		},
		{
			"name contains A to Z",
			filesWithProposalName(t, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
			nil,
		},
		{
			"name contains a to z",
			filesWithProposalName(t, "abcdefghijklmnopqrstuvwxyz"),
			nil,
		},
		{
			"name contains 0 to 9",
			filesWithProposalName(t, "0123456789"),
			nil,
		},
		{
			"name contains supported chars",
			filesWithProposalName(t, "&.,:;- @+#/()!?\"'"),
			nil,
		},
		{
			"name contains newline",
			filesWithProposalName(t, "proposal name\n"),
			errNameInvalid,
		},
		{
			"name contains tab",
			filesWithProposalName(t, "proposal name\t"),
			errNameInvalid,
		},
		{
			"name contains brackets",
			filesWithProposalName(t, "{proposal name}"),
			errNameInvalid,
		},
		{
			"name is valid lowercase",
			filesWithProposalName(t, "proposal name"),
			nil,
		},
		{
			"name is valid mixed case",
			filesWithProposalName(t, "Proposal Name"),
			nil,
		},
	}
}

// fileProposalIndex returns a backend file for a proposal index file.
func fileProposalIndex() backend.File {
	var (
		text    = "Hello, world. This is my proposal. Pay me."
		payload = []byte(text)
	)
	return backend.File{
		Name:    pi.FileNameIndexFile,
		MIME:    "text/plain; charset=utf-8",
		Digest:  hex.EncodeToString(util.Digest(payload)),
		Payload: base64.StdEncoding.EncodeToString(payload),
	}
}

// fileProposalMetadata returns a backend file for a proposal metadata file.
// The proposal metadata can optionally be provided as an argument. If no
// proposal metadata is provided, one is created and filled with test data.
func fileProposalMetadata(t *testing.T, pm *pi.ProposalMetadata) backend.File {
	if pm == nil {
		pm = &pi.ProposalMetadata{
			Name: "Test Proposal Name",
		}
	}
	pmb, err := json.Marshal(pm)
	if err != nil {
		t.Fatal(err)
	}
	return backend.File{
		Name:    pi.FileNameProposalMetadata,
		MIME:    "text/plain; charset=utf-8",
		Digest:  hex.EncodeToString(util.Digest(pmb)),
		Payload: base64.StdEncoding.EncodeToString(pmb),
	}
}

// filesForProposal returns the backend files for a valid proposal. The
// returned files only include the files required by the pi plugin API. No
// attachment files are included. The caller can pass in additional files that
// will be included in the returned list.
func filesForProposal(t *testing.T, files ...backend.File) []backend.File {
	fs := []backend.File{
		fileProposalIndex(),
		fileProposalMetadata(t, nil),
	}
	for _, v := range files {
		fs = append(fs, v)
	}
	return fs
}

// filesWithNoProposalName returns the backend files for a valid proposal,
// using the provided name as the proposal name. The returned files only
// include the files required by the pi plugin API. No attachment files are
// included.
func filesWithProposalName(t *testing.T, name string) []backend.File {
	return []backend.File{
		fileProposalIndex(),
		fileProposalMetadata(t, &pi.ProposalMetadata{
			Name: name,
		}),
	}
}
