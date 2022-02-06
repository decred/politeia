// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io/ioutil"
	"math/rand"
	"path/filepath"
	"strings"
	"time"

	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/api/v1/mime"
	pi "github.com/decred/politeia/politeiad/plugins/pi"
	piplugin "github.com/decred/politeia/politeiad/plugins/pi"
	piv1 "github.com/decred/politeia/politeiawww/api/pi/v1"
	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
	"github.com/decred/politeia/util"
)

const (
	monthInSeconds      int64 = 30 * 24 * 60 * 60
	fourMonthsInSeconds int64 = 4 * monthInSeconds
)

var (
	// defaultStartDate is the default proposal metadata start date in
	// Unix time. It defaults to one month from now.
	defaultStartDate = time.Now().Unix() + monthInSeconds

	// defaultEndDate is the default proposal metadata end date in
	// Unix time. It defaults to four months from now.
	defaultEndDate = time.Now().Unix() + fourMonthsInSeconds

	// defaultAmount is the default proposal metadata amount in cents.
	// It defaults to $20k in cents.
	defaultAmount uint64 = 2000000
)

func printProposalFiles(files []rcv1.File) error {
	for _, v := range files {
		b, err := base64.StdEncoding.DecodeString(v.Payload)
		if err != nil {
			return err
		}
		size := byteCountSI(int64(len(b)))
		printf("  %-22v %-26v %v\n", v.Name, v.MIME, size)
	}

	// A vote metadata file is optional
	var isRFP bool
	vm, err := pclient.VoteMetadataDecode(files)
	if err != nil {
		return err
	}
	if vm != nil {
		if vm.LinkBy != 0 {
			isRFP = true
		}
	}

	// Its possible for a proposal metadata to not exist if the
	// proposal has been censored.
	pm, err := pclient.ProposalMetadataDecode(files)
	if err == nil {
		printf("%v\n", piv1.FileNameProposalMetadata)
		switch {
		case !isRFP:
			printf("  Name      : %v\n", pm.Name)
			printf("  Domain    : %v\n", pm.Domain)
			printf("  Amount    : %v\n", dollars(int64(pm.Amount)))
			printf("  Start Date: %v\n", dateAndTimeFromUnix(pm.StartDate))
			printf("  End Date  : %v\n", dateAndTimeFromUnix(pm.EndDate))
		case isRFP:
			printf("  Name  : %v\n", pm.Name)
			printf("  Domain: %v\n", pm.Domain)
		}
	}

	// Print vote metadata if exists.
	if vm != nil {
		printf("%v\n", piv1.FileNameVoteMetadata)
		if vm.LinkTo != "" {
			printf("  LinkTo: %v\n", vm.LinkTo)
		}
		if vm.LinkBy != 0 {
			printf("  LinkBy: %v\n", dateAndTimeFromUnix(vm.LinkBy))
		}
	}

	return nil
}

func printProposal(r rcv1.Record) error {
	printf("Token    : %v\n", r.CensorshipRecord.Token)
	printf("Version  : %v\n", r.Version)
	printf("State    : %v\n", rcv1.RecordStates[r.State])
	printf("Status   : %v\n", rcv1.RecordStatuses[r.Status])
	printf("Timestamp: %v\n", dateAndTimeFromUnix(r.Timestamp))
	printf("Username : %v\n", r.Username)
	printf("Merkle   : %v\n", r.CensorshipRecord.Merkle)
	printf("Receipt  : %v\n", r.CensorshipRecord.Signature)
	printf("Metadata\n")
	for _, v := range r.Metadata {
		size := byteCountSI(int64(len([]byte(v.Payload))))
		printf("  %-8v %-2v %v\n", v.PluginID, v.StreamID, size)
	}
	printf("Files\n")
	return printProposalFiles(r.Files)
}

// printProposalSummary prints a proposal summary.
func printProposalSummary(token string, s piv1.Summary) {
	printf("Token : %v\n", token)
	printf("Status: %v\n", s.Status)
}

// printBillingStatusChanges prints a proposal billing status change.
func printBillingStatusChange(bsc piv1.BillingStatusChange) {
	printf("  Token    : %v\n", bsc.Token)
	printf("  Status   : %v\n", piv1.BillingStatuses[bsc.Status])
	if bsc.Reason != "" {
		printf("  Reason   : %v\n", bsc.Reason)
	}
	printf("  PublicKey: %v\n", bsc.PublicKey)
	printf("  Signature: %v\n", bsc.Signature)
	printf("  Receipt  : %v\n", bsc.Receipt)
	printf("  Timestamp: %v\n", dateAndTimeFromUnix(bsc.Timestamp))
}

// indexFileRandom returns a proposal index file filled with random data.
func indexFileRandom(sizeInBytes int) (*rcv1.File, error) {
	// Create lines of text that are 80 characters long
	charSet := "abcdefghijklmnopqrstuvwxyz"
	var b strings.Builder
	for i := 0; i < sizeInBytes; i++ {
		if i != 0 && i%80 == 0 {
			b.WriteString("\n")
			continue
		}
		r := rand.Intn(len(charSet))
		char := charSet[r]
		b.WriteString(string(char))
	}
	b.WriteString("\n")
	payload := []byte(b.String())

	return &rcv1.File{
		Name:    piv1.FileNameIndexFile,
		MIME:    mime.DetectMimeType(payload),
		Digest:  hex.EncodeToString(util.Digest(payload)),
		Payload: base64.StdEncoding.EncodeToString(payload),
	}, nil
}

// pngFileRandom returns a record file for a randomly generated PNG image. The
// size of the image will be 0.49MB.
func pngFileRandom() (*rcv1.File, error) {
	b := new(bytes.Buffer)
	img := image.NewRGBA(image.Rect(0, 0, 500, 250))

	// Fill in the pixels with random rgb colors
	r := rand.New(rand.NewSource(255))
	for y := 0; y < img.Bounds().Max.Y-1; y++ {
		for x := 0; x < img.Bounds().Max.X-1; x++ {
			a := uint8(r.Float32() * 255)
			rgb := uint8(r.Float32() * 255)
			img.SetRGBA(x, y, color.RGBA{rgb, rgb, rgb, a})
		}
	}
	err := png.Encode(b, img)
	if err != nil {
		return nil, err
	}

	// Create a random name
	rn, err := util.Random(8)
	if err != nil {
		return nil, err
	}

	return &rcv1.File{
		Name:    hex.EncodeToString(rn) + ".png",
		MIME:    mime.DetectMimeType(b.Bytes()),
		Digest:  hex.EncodeToString(util.Digest(b.Bytes())),
		Payload: base64.StdEncoding.EncodeToString(b.Bytes()),
	}, nil
}

func proposalFilesRandom(textFileSize, imageFileCountMax int) ([]rcv1.File, error) {
	files := make([]rcv1.File, 0, 16)

	// Generate random text for the index file
	f, err := indexFileRandom(textFileSize)
	if err != nil {
		return nil, err
	}
	files = append(files, *f)

	// Generate a random number of attachment files
	if imageFileCountMax > 0 {
		attachmentCount := rand.Intn(imageFileCountMax)
		for i := 0; i <= attachmentCount; i++ {
			f, err := pngFileRandom()
			if err != nil {
				return nil, err
			}
			files = append(files, *f)
		}
	}

	return files, nil
}

func proposalFilesFromDisk(indexFile string, attachments []string) ([]rcv1.File, error) {
	files := make([]rcv1.File, 0, len(attachments)+1)

	// Setup index file
	fp := util.CleanAndExpandPath(indexFile)
	var err error
	payload, err := ioutil.ReadFile(fp)
	if err != nil {
		return nil, fmt.Errorf("ReadFile %v: %v", fp, err)
	}
	files = append(files, rcv1.File{
		Name:    piplugin.FileNameIndexFile,
		MIME:    mime.DetectMimeType(payload),
		Digest:  hex.EncodeToString(util.Digest(payload)),
		Payload: base64.StdEncoding.EncodeToString(payload),
	})

	// Setup attachment files
	for _, fn := range attachments {
		fp := util.CleanAndExpandPath(fn)
		payload, err := ioutil.ReadFile(fp)
		if err != nil {
			return nil, fmt.Errorf("ReadFile %v: %v", fp, err)
		}

		files = append(files, rcv1.File{
			Name:    filepath.Base(fn),
			MIME:    mime.DetectMimeType(payload),
			Digest:  hex.EncodeToString(util.Digest(payload)),
			Payload: base64.StdEncoding.EncodeToString(payload),
		})
	}

	return files, nil
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

// parseProposalStatus parses a pi PropStatusT from the provided string. A
// PropStatusInvalid is returned if the provided string does not correspond to
// a valid proposal status.
func parseProposalStatus(status string) pi.PropStatusT {
	switch pi.PropStatusT(status) {
	// The following are valid proposal statuses
	case pi.PropStatusUnvetted,
		pi.PropStatusUnvettedAbandoned,
		pi.PropStatusUnvettedCensored,
		pi.PropStatusUnderReview,
		pi.PropStatusAbandoned,
		pi.PropStatusCensored,
		pi.PropStatusVoteAuthorized,
		pi.PropStatusVoteStarted,
		pi.PropStatusApproved,
		pi.PropStatusRejected,
		pi.PropStatusActive,
		pi.PropStatusCompleted,
		pi.PropStatusClosed:
	default:
		return pi.PropStatusInvalid
	}
	return pi.PropStatusT(status)
}
