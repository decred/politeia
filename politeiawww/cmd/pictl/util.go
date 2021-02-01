// Copyright (c) 2017-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/api/v1/mime"
	piplugin "github.com/decred/politeia/politeiad/plugins/pi"
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

// indexFileRandom returns a proposal index file filled with random data.
// TODO fill to max size
func indexFileRandom() (*rcv1.File, error) {
	var b bytes.Buffer
	for i := 0; i < 10; i++ {
		r, err := util.Random(32)
		if err != nil {
			return nil, err
		}
		b.WriteString(base64.StdEncoding.EncodeToString(r) + "\n")
	}

	return &rcv1.File{
		Name:    piplugin.FileNameIndexFile,
		MIME:    mime.DetectMimeType(b.Bytes()),
		Digest:  hex.EncodeToString(util.Digest(b.Bytes())),
		Payload: base64.StdEncoding.EncodeToString(b.Bytes()),
	}, nil
}
