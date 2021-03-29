// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	"github.com/decred/politeia/politeiawww/client"
)

// recordBundle represents the record bundle that is available for download
// in politeiagui.
type recordBundle struct {
	Record          rcv1.Record `json:"record"`
	ServerPublicKey string      `json:"serverpublickey"`
}

// verifyRecordBundle verifies that a record bundle has been accepted by
// politeia and that all user signatures are correct. A record bundle is the
// JSON data file that is downloaded from politeiagui for a record.
func verifyRecordBundle(rb recordBundle) error {
	// Verify censorship record
	err := client.RecordVerify(rb.Record, rb.ServerPublicKey)
	if err != nil {
		return fmt.Errorf("could not verify record: %v", err)
	}

	fmt.Printf("Server public key: %v\n", rb.ServerPublicKey)
	fmt.Printf("Censorship record:\n")
	fmt.Printf("  Token      : %v\n", rb.Record.CensorshipRecord.Token)
	fmt.Printf("  Merkle root: %v\n", rb.Record.CensorshipRecord.Merkle)
	fmt.Printf("  Signature  : %v\n", rb.Record.CensorshipRecord.Signature)
	fmt.Printf("\n")
	fmt.Printf("Censorship record verified\n")

	// Verify user metadata
	err = client.UserMetadataVerify(rb.Record.Metadata, rb.Record.Files)
	if err != nil {
		return err
	}

	fmt.Printf("User signature verified\n")

	// Verify status change signatures
	err = client.StatusChangesVerify(rb.Record.Metadata)
	if err != nil {
		return err
	}

	fmt.Printf("Status change signatures verified\n")

	return nil
}

// verifyRecordBundleFile takes the filepath of a record bundle and verifies
// the contents of the file.
func verifyRecordBundleFile(fp string) error {
	// Decode record bundle
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		return err
	}
	var rb recordBundle
	err = json.Unmarshal(b, &rb)
	if err != nil {
		return fmt.Errorf("could not unmarshal record bundle: %v", err)
	}

	// Verify record bundle
	return verifyRecordBundle(rb)
}

// verifyRecordTimestampsFile takes the filepath of record timestamps and
// verifies the contents of the file.
func verifyRecordTimestampsFile(fp string) error {
	// Decode timestamps reply
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		return err
	}
	var tr rcv1.TimestampsReply
	err = json.Unmarshal(b, &tr)
	if err != nil {
		return fmt.Errorf("could not unmarshal record timestamps: %v", err)
	}

	// Verify timestamps
	err = client.RecordTimestampsVerify(tr)
	if err != nil {
		return err
	}

	fmt.Printf("Record timestamps verified\n")

	return nil
}
