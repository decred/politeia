// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/api/v1/mime"
	pi "github.com/decred/politeia/politeiawww/api/pi/v1"
	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	v1 "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/util"
)

// signedMerkleRoot calculates the merkle root of the passed in list of files
// and metadata, signs the merkle root with the passed in identity and returns
// the signature.
func signedMerkleRoot(files []rcv1.File, id *identity.FullIdentity) (string, error) {
	/*
		if len(files) == 0 {
			return "", fmt.Errorf("no proposal files found")
		}
		mr, err := utilwww.MerkleRoot(files, md)
		if err != nil {
			return "", err
		}
		sig := id.SignMessage([]byte(mr))
		return hex.EncodeToString(sig[:]), nil
	*/
	return "", fmt.Errorf("not implemented")
}

// convertTicketHashes converts a slice of hexadecimal ticket hashes into
// a slice of byte slices.
func convertTicketHashes(h []string) ([][]byte, error) {
	hashes := make([][]byte, 0, len(h))
	for _, v := range h {
		h, err := chainhash.NewHashFromStr(v)
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, h[:])
	}
	return hashes, nil
}

// createMDFile returns a File object that was created using a markdown file
// filled with random text.
func createMDFile() (*pi.File, error) {
	var b bytes.Buffer
	b.WriteString("This is the proposal title\n")

	for i := 0; i < 10; i++ {
		r, err := util.Random(32)
		if err != nil {
			return nil, err
		}
		b.WriteString(base64.StdEncoding.EncodeToString(r) + "\n")
	}

	return &pi.File{
		Name:    v1.PolicyIndexFilename,
		MIME:    mime.DetectMimeType(b.Bytes()),
		Digest:  hex.EncodeToString(util.Digest(b.Bytes())),
		Payload: base64.StdEncoding.EncodeToString(b.Bytes()),
	}, nil
}

func verifyDigests(files []rcv1.File) error {
	// Validate file digests
	for _, f := range files {
		b, err := base64.StdEncoding.DecodeString(f.Payload)
		if err != nil {
			return fmt.Errorf("file: %v decode payload err %v",
				f.Name, err)
		}
		digest := util.Digest(b)
		d, ok := util.ConvertDigest(f.Digest)
		if !ok {
			return fmt.Errorf("file: %v invalid digest %v",
				f.Name, f.Digest)
		}
		if !bytes.Equal(digest, d[:]) {
			return fmt.Errorf("file: %v digests do not match",
				f.Name)
		}
	}

	return nil
}

func verifyRecord(r rcv1.Record, serverPubKey string) error {
	/*
		if len(p.Files) > 0 {
			// Verify digests
			err := verifyDigests(p.Files, p.Metadata)
			if err != nil {
				return err
			}
			// Verify merkle root
			mr, err := utilwww.MerkleRoot(p.Files, p.Metadata)
			if err != nil {
				return err
			}
			// Check if merkle roots match
			if mr != p.CensorshipRecord.Merkle {
				return fmt.Errorf("merkle roots do not match")
			}
		}

		// Verify proposal signature
		pid, err := util.IdentityFromString(p.PublicKey)
		if err != nil {
			return err
		}
		sig, err := util.ConvertSignature(p.Signature)
		if err != nil {
			return err
		}
		if !pid.VerifyMessage([]byte(p.CensorshipRecord.Merkle), sig) {
			return fmt.Errorf("invalid proposal signature")
		}

		// Verify censorship record signature
		id, err := util.IdentityFromString(serverPubKey)
		if err != nil {
			return err
		}
		s, err := util.ConvertSignature(p.CensorshipRecord.Signature)
		if err != nil {
			return err
		}
		msg := []byte(p.CensorshipRecord.Merkle + p.CensorshipRecord.Token)
		if !id.VerifyMessage(msg, s) {
			return fmt.Errorf("invalid censorship record signature")
		}

		return nil
	*/
	return fmt.Errorf("not implemented")
}
