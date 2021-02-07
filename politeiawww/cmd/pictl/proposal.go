// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"

	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/api/v1/mime"
	usplugin "github.com/decred/politeia/politeiad/plugins/user"
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
	return nil
}

func printProposal(r rcv1.Record) error {
	printf("Token    : %v\n", r.CensorshipRecord.Token)
	printf("Version  : %v\n", r.Version)
	printf("Status   : %v\n", rcv1.RecordStatuses[r.Status])
	printf("Timestamp: %v\n", r.Timestamp)
	printf("Username : %v\n", r.Username)
	printf("Merkle   : %v\n", r.CensorshipRecord.Merkle)
	printf("Receipt  : %v\n", r.CensorshipRecord.Signature)
	printf("Metadata\n")
	for _, v := range r.Metadata {
		size := byteCountSI(int64(len([]byte(v.Payload))))
		printf("  %-2v %v\n", v.ID, size)
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
			ID:      usplugin.MDStreamIDUserMetadata,
			Payload: string(umb),
		},
		{
			ID:      usplugin.MDStreamIDStatusChanges,
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
	m, err := util.MerkleRoot(digests)
	if err != nil {
		return "", err
	}
	mr := hex.EncodeToString(m[:])
	sig := fid.SignMessage([]byte(mr))
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
