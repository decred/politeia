// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math/rand"
	"strconv"
	"testing"

	"github.com/decred/dcrtime/merkle"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/api/v1/mime"
	www "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/database"
	"github.com/decred/politeia/util"
)

// createFilePNG creates a File that contains a png image.  The png image is
// blank by default but can be filled in with random rgb colors by setting the
// addColor parameter to true.  The png without color will be ~3kB.  The png
// with color will be ~2MB.
func createFilePNG(t *testing.T, addColor bool) *www.File {
	t.Helper()

	b := new(bytes.Buffer)
	img := image.NewRGBA(image.Rect(0, 0, 1000, 500))

	// Fill in the pixels with random rgb colors in order to
	// increase the size of the image. This is used to create an
	// image that exceeds the maximum image size policy.
	if addColor {
		r := rand.New(rand.NewSource(255))
		for y := 0; y < img.Bounds().Max.Y-1; y++ {
			for x := 0; x < img.Bounds().Max.X-1; x++ {
				a := uint8(r.Float32() * 255)
				rgb := uint8(r.Float32() * 255)
				img.SetRGBA(x, y, color.RGBA{rgb, rgb, rgb, a})
			}
		}
	}

	png.Encode(b, img)

	// Generate a random name
	r, err := util.Random(8)
	if err != nil {
		t.Fatalf("%v", err)
	}

	return &www.File{
		Name:    hex.EncodeToString(r) + ".png",
		MIME:    mime.DetectMimeType(b.Bytes()),
		Digest:  hex.EncodeToString(util.Digest(b.Bytes())),
		Payload: base64.StdEncoding.EncodeToString(b.Bytes()),
	}
}

// createFileMD creates a File that contains a markdown file.  The markdown
// file is filled with randomly generated data and adheres to the politeiawwww
// policies for markdown files.
func createFileMD(t *testing.T, size int, title string) *www.File {
	t.Helper()

	var b bytes.Buffer
	b.WriteString(title + "\n")
	r, err := util.Random(size)
	if err != nil {
		t.Fatalf("%v", err)
	}
	b.WriteString(base64.StdEncoding.EncodeToString(r) + "\n")

	return &www.File{
		Name:    indexFile,
		MIME:    mime.DetectMimeType(b.Bytes()),
		Digest:  hex.EncodeToString(util.Digest(b.Bytes())),
		Payload: base64.StdEncoding.EncodeToString(b.Bytes()),
	}
}

// createNewProposal computes the merkle root of the given files, signs the
// merkle root with the given identity then returns a NewProposal object.
func createNewProposal(t *testing.T, id *identity.FullIdentity, files []www.File) *www.NewProposal {
	t.Helper()

	if len(files) == 0 {
		t.Fatalf("no files found")
	}

	digests := make([]*[sha256.Size]byte, 0, len(files))
	for _, f := range files {
		d, ok := util.ConvertDigest(f.Digest)
		if !ok {
			t.Fatalf("could not convert digest %v", f.Digest)
		}
		digests = append(digests, &d)
	}
	root := hex.EncodeToString(merkle.Root(digests)[:])
	sig := id.SignMessage([]byte(root))

	return &www.NewProposal{
		Files:     files,
		PublicKey: hex.EncodeToString(id.Public.Key[:]),
		Signature: hex.EncodeToString(sig[:]),
	}
}

func TestValidateProposal(t *testing.T) {
	// Setup backend and user
	b := createBackend(t)
	defer b.db.Close()

	nu, id := createNewUser(t, b)
	user, err := b.UserGetByEmail(nu.Email)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Create test data
	md := createFileMD(t, 8, "Valid Title")
	png := createFilePNG(t, false)
	np := createNewProposal(t, id, []www.File{*md, *png})

	// Invalid signature
	propInvalidSig := &www.NewProposal{
		Files:     np.Files,
		PublicKey: np.PublicKey,
		Signature: "abc",
	}

	// Signature is valid but incorrect
	propBadSig := createNewProposal(t, id, []www.File{*md})
	if err != nil {
		t.Fatalf("%v", err)
	}
	propBadSig.Signature = np.Signature

	// No files
	propNoFiles := &www.NewProposal{
		Files:     make([]www.File, 0),
		PublicKey: np.PublicKey,
		Signature: np.Signature,
	}

	// Invalid markdown filename
	mdBadFilename := *md
	mdBadFilename.Name = "bad_filename.md"
	propBadFilename := createNewProposal(t, id, []www.File{mdBadFilename})

	// Duplicate filenames
	propDupFiles := createNewProposal(t, id, []www.File{*md, *png, *png})

	// Too many markdown files. We need one correctly named md
	// file and the rest must have their names changed so that we
	// don't get a duplicate filename error.
	files := make([]www.File, 0, www.PolicyMaxMDs+1)
	files = append(files, *md)
	for i := 0; i < www.PolicyMaxMDs; i++ {
		m := *md
		m.Name = fmt.Sprintf("%v.md", i)
		files = append(files, m)
	}
	propMaxMDFiles := createNewProposal(t, id, files)

	// Too many image files. All of their names must be different
	// so that we don't get a duplicate filename error.
	files = make([]www.File, 0, www.PolicyMaxImages+2)
	files = append(files, *md)
	for i := 0; i <= www.PolicyMaxImages; i++ {
		p := *png
		p.Name = fmt.Sprintf("%v.png", i)
		files = append(files, p)
	}
	propMaxImages := createNewProposal(t, id, files)

	// Markdown file too large
	mdLarge := createFileMD(t, www.PolicyMaxMDSize, "Valid Title")
	propMDLarge := createNewProposal(t, id, []www.File{*mdLarge, *png})

	// Image too large
	pngLarge := createFilePNG(t, true)
	propImageLarge := createNewProposal(t, id, []www.File{*md, *pngLarge})

	// Invalid proposal title
	mdBadTitle := createFileMD(t, 8, "{invalid-title}")
	propBadTitle := createNewProposal(t, id, []www.File{*mdBadTitle})

	// Setup test cases
	var tests = []struct {
		name        string
		newProposal www.NewProposal
		user        *database.User
		want        error
	}{
		{"correct proposal", *np, user, nil},

		{"invalid signature", *propInvalidSig, user,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidSignature,
			},
		},

		{"incorrect signature", *propBadSig, user,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidSignature,
			},
		},

		{"no files", *propNoFiles, user,
			www.UserError{
				ErrorCode: www.ErrorStatusProposalMissingFiles,
			},
		},

		{"bad md filename", *propBadFilename, user,
			www.UserError{
				ErrorCode: www.ErrorStatusProposalMissingFiles,
			},
		},

		{"duplicate filenames", *propDupFiles, user,
			www.UserError{
				ErrorCode: www.ErrorStatusProposalDuplicateFilenames,
			},
		},

		{"too may md files", *propMaxMDFiles, user,
			www.UserError{
				ErrorCode: www.ErrorStatusMaxMDsExceededPolicy,
			},
		},

		{"too many images", *propMaxImages, user,
			www.UserError{
				ErrorCode: www.ErrorStatusMaxImagesExceededPolicy,
			},
		},

		{"md file too large", *propMDLarge, user,
			www.UserError{
				ErrorCode: www.ErrorStatusMaxMDSizeExceededPolicy,
			},
		},

		{"image too large", *propImageLarge, user,
			www.UserError{
				ErrorCode: www.ErrorStatusMaxImageSizeExceededPolicy,
			},
		},

		{"invalid title", *propBadTitle, user,
			www.UserError{
				ErrorCode: www.ErrorStatusProposalInvalidTitle,
			},
		},
	}

	// Run test cases
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := b.validateProposal(test.newProposal, test.user)
			got := convertErrorToMsg(err)
			want := convertErrorToMsg(test.want)
			if got != want {
				t.Errorf("got %v, want %v", got, want)
			}
		})
	}
}

func TestFilterProposals(t *testing.T) {
	// Test proposal page size. Only a single page of proposals
	// should be returned.
	t.Run("proposal page size", func(t *testing.T) {
		pq := proposalsFilter{
			StateMap: map[www.PropStateT]bool{
				www.PropStateVetted: true,
			},
		}

		// We use simplified userIDs, timestamps, and censorship
		// record tokens. This is ok since filterProps() does not
		// check the validity of the data.
		c := www.ProposalListPageSize + 5
		propsPageTest := make([]www.ProposalRecord, 0, c)
		for i := 1; i <= c; i++ {
			propsPageTest = append(propsPageTest, www.ProposalRecord{
				State:     www.PropStateVetted,
				UserId:    strconv.Itoa(i),
				Timestamp: int64(i),
				CensorshipRecord: www.CensorshipRecord{
					Token: strconv.Itoa(i),
				},
			})
		}

		out := filterProps(pq, propsPageTest)
		if len(out) != www.ProposalListPageSize {
			t.Errorf("got %v, want %v", len(out), www.ProposalListPageSize)
		}
	})

	// Create data for test table. We use simplified userIDs,
	// timestamps, and censorship record tokens. This is ok since
	// filterProps() does not check the validity of the data.
	props := make(map[int]*www.ProposalRecord, 5)
	for i := 1; i <= 5; i++ {
		props[i] = &www.ProposalRecord{
			State:     www.PropStateVetted,
			UserId:    strconv.Itoa(i),
			Timestamp: int64(i),
			CensorshipRecord: www.CensorshipRecord{
				Token: strconv.Itoa(i),
			},
		}
	}

	// Change the State of a few proposals so that they are not
	// all the same
	props[2].State = www.PropStateUnvetted
	props[4].State = www.PropStateUnvetted

	// Setup tests
	var tests = []struct {
		name  string
		req   proposalsFilter
		input []www.ProposalRecord
		want  []www.ProposalRecord
	}{
		{"filter by State",
			proposalsFilter{
				StateMap: map[www.PropStateT]bool{
					www.PropStateUnvetted: true,
				},
			},
			[]www.ProposalRecord{
				*props[1], *props[2], *props[3], *props[4], *props[5],
			},
			[]www.ProposalRecord{
				*props[4], *props[2],
			},
		},

		{"filter by UserID",
			proposalsFilter{
				UserID: "1",
				StateMap: map[www.PropStateT]bool{
					www.PropStateVetted: true,
				},
			},
			[]www.ProposalRecord{
				*props[1], *props[2], *props[3], *props[4], *props[5],
			},
			[]www.ProposalRecord{
				*props[1],
			},
		},

		{"filter by Before",
			proposalsFilter{
				Before: props[3].CensorshipRecord.Token,
				StateMap: map[www.PropStateT]bool{
					www.PropStateUnvetted: true,
					www.PropStateVetted:   true,
				},
			},
			[]www.ProposalRecord{
				*props[1], *props[2], *props[3], *props[4], *props[5],
			},
			[]www.ProposalRecord{
				*props[5], *props[4],
			},
		},

		{"filter by After",
			proposalsFilter{
				After: props[3].CensorshipRecord.Token,
				StateMap: map[www.PropStateT]bool{
					www.PropStateUnvetted: true,
					www.PropStateVetted:   true,
				},
			},
			[]www.ProposalRecord{
				*props[1], *props[2], *props[3], *props[4], *props[5],
			},
			[]www.ProposalRecord{
				*props[2], *props[1],
			},
		},

		{"unsorted proposals",
			proposalsFilter{
				StateMap: map[www.PropStateT]bool{
					www.PropStateUnvetted: true,
					www.PropStateVetted:   true,
				},
			},
			[]www.ProposalRecord{
				*props[3], *props[4], *props[1], *props[5], *props[2],
			},
			[]www.ProposalRecord{
				*props[5], *props[4], *props[3], *props[2], *props[1],
			},
		},
	}

	// Run tests
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			out := filterProps(test.req, test.input)

			// Pull out the tokens to make it easier to view the
			// difference between want and got
			want := make([]string, len(test.want))
			for _, p := range test.want {
				want = append(want, p.CensorshipRecord.Token)
			}
			got := make([]string, len(out))
			for _, p := range out {
				got = append(got, p.CensorshipRecord.Token)
			}

			// Check if want and got are the same
			if len(want) != len(got) {
				goto fail
			}
			for i, w := range want {
				if w != got[i] {
					goto fail
				}
			}

			// success; want and got are the same
			return

		fail:
			t.Errorf("got %v, want %v", got, want)
		})
	}
}
