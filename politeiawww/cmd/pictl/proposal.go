// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"io/ioutil"
	"math/rand"
	"path/filepath"
	"strings"

	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/api/v1/mime"
	piplugin "github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/decred/politeia/politeiad/plugins/usermd"
	piv1 "github.com/decred/politeia/politeiawww/api/pi/v1"
	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	"github.com/decred/politeia/util"
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

	// Its possible for a proposal metadata to not exist if the
	// proposal has been censored.
	pm, err := proposalMetadataDecode(files)
	if err != nil {
		return err
	}
	if pm != nil {
		printf("%v\n", piv1.FileNameProposalMetadata)
		printf("  Name: %v\n", pm.Name)
	}

	// A vote metadata file is optional
	vm, err := voteMetadataDecode(files)
	if err != nil {
		return err
	}
	if vm != nil {
		printf("%v\n", piv1.FileNameVoteMetadata)
		if vm.LinkTo != "" {
			printf("  LinkTo: %v\n", vm.LinkTo)
		}
		if vm.LinkBy != 0 {
			printf("  LinkBy: %v\n", timestampFromUnix(vm.LinkBy))
		}
	}

	return nil
}

func printProposal(r rcv1.Record) error {
	printf("Token    : %v\n", r.CensorshipRecord.Token)
	printf("Version  : %v\n", r.Version)
	printf("Status   : %v\n", rcv1.RecordStatuses[r.Status])
	printf("Timestamp: %v\n", timestampFromUnix(r.Timestamp))
	printf("Username : %v\n", r.Username)
	printf("Merkle   : %v\n", r.CensorshipRecord.Merkle)
	printf("Receipt  : %v\n", r.CensorshipRecord.Signature)
	printf("Metadata\n")
	for _, v := range r.Metadata {
		size := byteCountSI(int64(len([]byte(v.Payload))))
		printf("  %-8v %-2v %v\n", v.PluginID, v.ID, size)
	}
	printf("Files\n")
	return printProposalFiles(r.Files)
}

func convertProposal(p piv1.Proposal) (*rcv1.Record, error) {
	// Setup files
	files := make([]rcv1.File, 0, len(p.Files))
	for _, v := range p.Files {
		files = append(files, rcv1.File{
			Name:    v.Name,
			MIME:    v.MIME,
			Digest:  v.Digest,
			Payload: v.Payload,
		})
	}

	// Setup metadata
	um := rcv1.UserMetadata{
		UserID:    p.UserID,
		PublicKey: p.PublicKey,
		Signature: p.Signature,
	}
	umb, err := json.Marshal(um)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	for _, v := range p.Statuses {
		sc := rcv1.StatusChange{
			Token:     v.Token,
			Version:   v.Version,
			Status:    rcv1.RecordStatusT(v.Status),
			Reason:    v.Reason,
			PublicKey: v.PublicKey,
			Signature: v.Signature,
			Timestamp: v.Timestamp,
		}
		b, err := json.Marshal(sc)
		if err != nil {
			return nil, err
		}
		buf.Write(b)
	}
	metadata := []rcv1.MetadataStream{
		{
			ID:      usermd.MDStreamIDUserMetadata,
			Payload: string(umb),
		},
		{
			ID:      usermd.MDStreamIDStatusChanges,
			Payload: buf.String(),
		},
	}

	return &rcv1.Record{
		State:     p.State,
		Status:    rcv1.RecordStatusT(p.Status),
		Version:   p.Version,
		Timestamp: p.Timestamp,
		Username:  p.Username,
		Metadata:  metadata,
		Files:     files,
		CensorshipRecord: rcv1.CensorshipRecord{
			Token:     p.CensorshipRecord.Token,
			Merkle:    p.CensorshipRecord.Merkle,
			Signature: p.CensorshipRecord.Signature,
		},
	}, nil
}

func convertRecord(r rcv1.Record) (*piv1.Proposal, error) {
	// Decode metadata streams
	var (
		um  usermd.UserMetadata
		sc  = make([]usermd.StatusChangeMetadata, 0, 16)
		err error
	)
	for _, v := range r.Metadata {
		switch v.ID {
		case usermd.MDStreamIDUserMetadata:
			err = json.Unmarshal([]byte(v.Payload), &um)
			if err != nil {
				return nil, err
			}
		case usermd.MDStreamIDStatusChanges:
			sc, err = statusChangesDecode([]byte(v.Payload))
			if err != nil {
				return nil, err
			}
		}
	}

	// Convert files
	files := make([]piv1.File, 0, len(r.Files))
	for _, v := range r.Files {
		files = append(files, piv1.File{
			Name:    v.Name,
			MIME:    v.MIME,
			Digest:  v.Digest,
			Payload: v.Payload,
		})
	}

	// Convert statuses
	statuses := make([]piv1.StatusChange, 0, len(sc))
	for _, v := range sc {
		statuses = append(statuses, piv1.StatusChange{
			Token:     v.Token,
			Version:   v.Version,
			Status:    piv1.PropStatusT(v.Status),
			Reason:    v.Reason,
			PublicKey: v.PublicKey,
			Signature: v.Signature,
			Timestamp: v.Timestamp,
		})
	}

	return &piv1.Proposal{
		Version:   r.Version,
		Timestamp: r.Timestamp,
		State:     r.State,
		Status:    piv1.PropStatusT(r.Status),
		UserID:    um.UserID,
		Username:  r.Username,
		PublicKey: um.PublicKey,
		Signature: um.Signature,
		Statuses:  statuses,
		Files:     files,
		CensorshipRecord: piv1.CensorshipRecord{
			Token:     r.CensorshipRecord.Token,
			Merkle:    r.CensorshipRecord.Merkle,
			Signature: r.CensorshipRecord.Signature,
		},
	}, nil
}

func statusChangesDecode(payload []byte) ([]usermd.StatusChangeMetadata, error) {
	statuses := make([]usermd.StatusChangeMetadata, 0, 16)
	d := json.NewDecoder(strings.NewReader(string(payload)))
	for {
		var sc usermd.StatusChangeMetadata
		err := d.Decode(&sc)
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, err
		}
		statuses = append(statuses, sc)
	}
	return statuses, nil
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

// proposalMetadataDecode decodes and returns the ProposalMetadata from the
// provided record files. nil is returned if a ProposalMetadata is not found.
func proposalMetadataDecode(files []rcv1.File) (*piv1.ProposalMetadata, error) {
	var propMD *piv1.ProposalMetadata
	for _, v := range files {
		if v.Name == piv1.FileNameProposalMetadata {
			b, err := base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				return nil, err
			}
			var m piv1.ProposalMetadata
			err = json.Unmarshal(b, &m)
			if err != nil {
				return nil, err
			}
			propMD = &m
			break
		}
	}
	return propMD, nil
}

// voteMetadataDecode decodes and returns the VoteMetadata from the provided
// backend files. If a VoteMetadata is not found, nil will be returned.
func voteMetadataDecode(files []rcv1.File) (*piv1.VoteMetadata, error) {
	var voteMD *piv1.VoteMetadata
	for _, v := range files {
		if v.Name == piv1.FileNameVoteMetadata {
			b, err := base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				return nil, err
			}
			var vm piv1.VoteMetadata
			err = json.Unmarshal(b, &vm)
			if err != nil {
				return nil, err
			}
			voteMD = &vm
			break
		}
	}
	return voteMD, nil
}
