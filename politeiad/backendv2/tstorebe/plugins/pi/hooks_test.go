// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/decred/politeia/util"
)

func TestProposalNameIsValid(t *testing.T) {
	// Setup pi plugin
	p, cleanup := newTestPiPlugin(t)
	defer cleanup()

	tests := []struct {
		name string
		want bool
	}{
		// empty test
		{
			"",
			false,
		},
		// 7 characters
		{
			"abcdefg",
			false,
		},

		// 81 characters
		{
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			false,
		},
		// 8 characters
		{
			"12345678",
			true,
		},
		{
			"valid title",
			true,
		},
		{
			" - title: is valid; title. !.,  ",
			true,
		},
		{
			" - title: is valid; title.   ",
			true,
		},
		{
			"\n\n#This-is MY tittle###",
			false,
		},
		{
			"{this-is-the-title}",
			false,
		},
		{
			"\t<this- is-the title>",
			false,
		},
		{
			"{this   -is-the-title}   ",
			false,
		},
		{
			"###this is the title***",
			false,
		},
		{
			"###this is the title@+",
			true,
		},
	}
	for _, test := range tests {
		t.Run("", func(t *testing.T) {
			isValid := p.proposalNameIsValid(test.name)
			if isValid != test.want {
				t.Errorf("got %v, want %v", isValid, test.want)
			}
		})
	}
}

type proposalTest struct {
	name string

	files []backend.File // Input
	err   error          // Output
}

func fileIndex() backend.File {
	var (
		text = `Hello, world. This is my proposal. It would be
            really cool if you could approve it and pay me
            all the moneys. DCR to the moon!`

		payload = []byte(text)
	)
	return backend.File{
		Name:    pi.FileNameIndexFile,
		MIME:    "text/plain; charset=utf-8",
		Digest:  hex.EncodeToString(util.Digest(payload)),
		Payload: base64.StdEncoding.EncodeToString(payload),
	}
}

// fileProposalMetadata returns a backend file for a proposal metadata. The
// proposal metadata can optionally be provided as an argument. If no proposal
// metadata is provided, one is created and filled with test data.
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

func filesNoAttachments(t *testing.T) []backend.File {
	return []backend.File{
		fileIndex(),
		fileProposalMetadata(t, nil),
	}
}

func filesWithProposalName(t *testing.T, name string) []backend.File {
	return []backend.File{
		fileIndex(),
		fileProposalMetadata(t, &pi.ProposalMetadata{
			Name: name,
		}),
	}
}

func proposalNameTests(t *testing.T) []proposalTest {
	var (
		nameTooLong = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

		errNameInvalid = backend.PluginError{
			PluginID:  pi.PluginID,
			ErrorCode: uint32(pi.ErrorCodeProposalNameInvalid),
		}
	)
	return []proposalTest{
		{
			"proposal name empty",
			filesWithProposalName(t, ""),
			errNameInvalid,
		},
		{
			"proposal name too short", // 7 characters
			filesWithProposalName(t, "abcdefg"),
			errNameInvalid,
		},

		// 81 characters
		{
			"proposal name too long", // 81 characters
			filesWithProposalName(t, nameTooLong),
			errNameInvalid,
		},
		{
			"proposal name min length", // 8 characters
			"12345678",
			nil,
		},
		{
			"valid title",
			nil,
		},
		{
			" - title: is valid; title. !.,  ",
			nil,
		},
		{
			" - title: is valid; title.   ",
			nil,
		},
		{
			"\n\n#This-is MY tittle###",
			errNameInvalid,
		},
		{
			"{this-is-the-title}",
			errNameInvalid,
		},
		{
			"\t<this- is-the title>",
			errNameInvalid,
		},
		{
			"{this   -is-the-title}   ",
			errNameInvalid,
		},
		{
			"###this is the title***",
			errNameInvalid,
		},
		{
			"###this is the title@+",
			nil,
		},
	}
}

// proposalTests returns a list of tests that verify the files of a proposal
// meet all formatting criteria that the pi plugin requires.
func proposalTests() []proposalTest {
	return []proposalTest{
		{
			"text file name invalid",
			[]backend.File{},
			pi.ErrorCodeTextFileNameInvalid,
		},
		{
			"text file size invalid",
			[]backend.File{},
			pi.ErrorCodeTextFileSizeInvalid,
		},
		{
			"image file size invalid",
			[]backend.File{},
			pi.ErrorCodeImageFileSizeInvalid,
		},
		{
			"index file missing",
			[]backend.File{},
			pi.ErrorCodeTextFileMissing,
		},
		{
			"too many images",
			[]backend.File{},
			pi.ErrorCodeImageFileCountInvalid,
		},
		{
			"proposal metadata missing",
			[]backend.File{},
			pi.ErrorCodeTextFileMissing,
		},
		{
			"proposal name invalid",
			[]backend.File{},
		},
	}
}

func TestProposalFilesVerify(t *testing.T) {
	var tests = []struct {
		name string
	}{}
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
		})
	}
}
