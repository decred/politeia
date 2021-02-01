// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package client

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	"github.com/decred/politeia/util"
)

// RecordNew sends a records v1 New request to politeiawww.
func (c *Client) RecordNew(n rcv1.New) (*rcv1.NewReply, error) {
	route := rcv1.APIRoute + rcv1.RouteNew
	resBody, err := c.makeReq(http.MethodPost, route, n)
	if err != nil {
		return nil, err
	}

	var nr rcv1.NewReply
	err = json.Unmarshal(resBody, &nr)
	if err != nil {
		return nil, err
	}

	return &nr, nil
}

// RecordDetails sends a records v1 Details request to politeiawww.
func (c *Client) RecordDetails(d rcv1.Details) (*rcv1.DetailsReply, error) {
	route := rcv1.APIRoute + rcv1.RouteDetails
	resBody, err := c.makeReq(http.MethodPost, route, d)
	if err != nil {
		return nil, err
	}

	var dr rcv1.DetailsReply
	err = json.Unmarshal(resBody, &dr)
	if err != nil {
		return nil, err
	}

	return &dr, nil
}

// digestsVerify verifies that all file digests match the calculated SHA256
// digests of the file payloads.
func digestsVerify(files []rcv1.File) error {
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

// RecordVerify verifies the censorship record of a records v1 Record.
func RecordVerify(r rcv1.Record, serverPubKey string) error {
	// Verify censorship record merkle root
	if len(r.Files) > 0 {
		// Verify digests
		err := digestsVerify(r.Files)
		if err != nil {
			return err
		}
		// Verify merkle root
		digests := make([]string, 0, len(r.Files))
		for _, v := range r.Files {
			digests = append(digests, v.Digest)
		}
		mr, err := util.MerkleRoot(digests)
		if err != nil {
			return err
		}
		if hex.EncodeToString(mr[:]) != r.CensorshipRecord.Merkle {
			return fmt.Errorf("merkle roots do not match")
		}
	}

	// Verify censorship record signature
	id, err := util.IdentityFromString(serverPubKey)
	if err != nil {
		return err
	}
	s, err := util.ConvertSignature(r.CensorshipRecord.Signature)
	if err != nil {
		return err
	}
	msg := []byte(r.CensorshipRecord.Merkle + r.CensorshipRecord.Token)
	if !id.VerifyMessage(msg, s) {
		return fmt.Errorf("invalid censorship record signature")
	}

	return nil
}
