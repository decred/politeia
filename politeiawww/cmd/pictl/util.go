// Copyright (c) 2017-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"

	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/api/v1/mime"
	piv1 "github.com/decred/politeia/politeiawww/api/pi/v1"
	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	"github.com/decred/politeia/util"
)

// printf prints the provided string to stdout if the global config settings
// allows for it.
func printf(s string, args ...interface{}) {
	switch {
	case cfg.Verbose, cfg.RawJSON:
		// These are handled by the politeiawwww client
	case cfg.Silent:
		// Do nothing
	default:
		// Print to stdout
		fmt.Printf(s, args...)
	}
}

// println prints the provided string to stdout if the global config settings
// allows for it.
func println(s string, args ...interface{}) {
	printf(s+"\n", args...)
}

// formatJSON returns a pretty printed JSON string for the provided structure.
func formatJSON(v interface{}) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return ""
	}
	return string(b)
}

// byteCountSI converts the provided bytes to a string representation of the
// closest SI unit (kB, MB, GB, etc).
func byteCountSI(b int64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB",
		float64(b)/float64(div), "kMGTPE"[exp])
}

func printProposalFiles(files []rcv1.File) error {
	for _, v := range files {
		b, err := base64.StdEncoding.DecodeString(v.Payload)
		if err != nil {
			return err
		}
		s := byteCountSI(int64(len(b)))
		printf("  %-22v %-26v %v\n", v.Name, v.MIME, s)
	}
	return nil
}

func printProposal(r rcv1.Record) error {
	printf("Token: %v\n", r.CensorshipRecord.Token)
	return printProposalFiles(r.Files)
}

// indexFileRandom returns a proposal index file filled with random data.
func indexFileRandom(sizeInBytes int) (*rcv1.File, error) {
	// Create lines of text that are 80 characters long
	charSet := "abcdefghijklmnopqrstuvwxyz"
	var b strings.Builder
	for i := 0; i < sizeInBytes; i++ {
		if i%80 == 0 && i != 0 {
			b.WriteString("\n")
			continue
		}
		r := rand.Intn(len(charSet))
		char := charSet[r]
		b.WriteString(string(char))
	}
	payload := []byte(b.String())

	return &rcv1.File{
		Name:    piv1.FileNameIndexFile,
		MIME:    mime.DetectMimeType(payload),
		Digest:  hex.EncodeToString(util.Digest(payload)),
		Payload: base64.StdEncoding.EncodeToString(payload),
	}, nil
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
	mr, err := util.MerkleRoot(digests)
	if err != nil {
		return "", err
	}
	sig := fid.SignMessage(mr[:])
	return hex.EncodeToString(sig[:]), nil
}

// proposalMetadataDecode decodes and returns the ProposalMetadata from the
// provided record files. An error is returned if a ProposalMetadata is not
// found.
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
	if propMD == nil {
		return nil, fmt.Errorf("proposal metadata not found")
	}
	return propMD, nil
}

// voteMetadataDecode decodes and returns the VoteMetadata from the provided
// backend files. If a VoteMetadata is not found, an empty one will be
// returned.
func voteMetadataDecode(files []rcv1.File) (*piv1.VoteMetadata, error) {
	var vm piv1.VoteMetadata
	for _, v := range files {
		if v.Name == piv1.FileNameVoteMetadata {
			b, err := base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				return nil, err
			}
			err = json.Unmarshal(b, &vm)
			if err != nil {
				return nil, err
			}
			break
		}
	}
	return &vm, nil
}
