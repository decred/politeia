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
	resBody, err := c.makeReq(http.MethodPost,
		rcv1.APIRoute, rcv1.RouteNew, n)
	if err != nil {
		return nil, err
	}

	var nr rcv1.NewReply
	err = json.Unmarshal(resBody, &nr)
	if err != nil {
		return nil, err
	}
	if c.verbose {
		fmt.Printf("%v\n", util.FormatJSON(nr))
	}

	return &nr, nil
}

// RecordEdit sends a records v1 Edit request to politeiawww.
func (c *Client) RecordEdit(e rcv1.Edit) (*rcv1.EditReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		rcv1.APIRoute, rcv1.RouteEdit, e)
	if err != nil {
		return nil, err
	}

	var er rcv1.EditReply
	err = json.Unmarshal(resBody, &er)
	if err != nil {
		return nil, err
	}
	if c.verbose {
		fmt.Printf("%v\n", util.FormatJSON(er))
	}

	return &er, nil
}

// RecordSetStatus sends a records v1 SetStatus request to politeiawww.
func (c *Client) RecordSetStatus(ss rcv1.SetStatus) (*rcv1.SetStatusReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		rcv1.APIRoute, rcv1.RouteSetStatus, ss)
	if err != nil {
		return nil, err
	}

	var ssr rcv1.SetStatusReply
	err = json.Unmarshal(resBody, &ssr)
	if err != nil {
		return nil, err
	}
	if c.verbose {
		fmt.Printf("%v\n", util.FormatJSON(ssr))
	}

	return &ssr, nil
}

// RecordDetails sends a records v1 Details request to politeiawww.
func (c *Client) RecordDetails(d rcv1.Details) (*rcv1.Record, error) {
	resBody, err := c.makeReq(http.MethodPost,
		rcv1.APIRoute, rcv1.RouteDetails, d)
	if err != nil {
		return nil, err
	}

	var dr rcv1.DetailsReply
	err = json.Unmarshal(resBody, &dr)
	if err != nil {
		return nil, err
	}
	if c.verbose {
		fmt.Printf("%v\n", util.FormatJSON(dr))
	}

	return &dr.Record, nil
}

// RecordInventory sends a records v1 Inventory request to politeiawww.
func (c *Client) RecordInventory(i rcv1.Inventory) (*rcv1.InventoryReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		rcv1.APIRoute, rcv1.RouteInventory, i)
	if err != nil {
		return nil, err
	}

	var ir rcv1.InventoryReply
	err = json.Unmarshal(resBody, &ir)
	if err != nil {
		return nil, err
	}
	if c.verbose {
		fmt.Printf("%v\n", util.FormatJSON(ir))
	}

	return &ir, nil
}

// RecordTimestamps sends a records v1 Timestamps request to politeiawww.
func (c *Client) RecordTimestamps(t rcv1.Timestamps) (*rcv1.TimestampsReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		rcv1.APIRoute, rcv1.RouteTimestamps, t)
	if err != nil {
		return nil, err
	}

	var tr rcv1.TimestampsReply
	err = json.Unmarshal(resBody, &tr)
	if err != nil {
		return nil, err
	}
	if c.verbose {
		fmt.Printf("%v\n", util.FormatJSON(tr))
	}

	return &tr, nil
}

// UserRecords sends a records v1 UserRecords request to politeiawww.
func (c *Client) UserRecords(ur rcv1.UserRecords) (*rcv1.UserRecordsReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		rcv1.APIRoute, rcv1.RouteUserRecords, ur)
	if err != nil {
		return nil, err
	}

	var urr rcv1.UserRecordsReply
	err = json.Unmarshal(resBody, &urr)
	if err != nil {
		return nil, err
	}
	if c.verbose {
		fmt.Printf("%v\n", util.FormatJSON(urr))
	}

	return &urr, nil
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
