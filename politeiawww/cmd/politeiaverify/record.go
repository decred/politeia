// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/decred/politeia/politeiad/backend"
	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	"github.com/decred/politeia/politeiawww/client"
)

// recordBundle represents the record bundle that is available for download
// in politeiagui.
type recordBundle struct {
	Record          rcv1.Record `json:"record"`
	ServerPublicKey string      `json:"serverpublickey"`
}

// verifyRecordBundle takes the file path of a record bundle file and verifies
// that the record bundle has been accepted by politeia and that all user
// signatures are correct.
func verifyRecordBundle(fp string) error {
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

	// Verify censorship record
	fmt.Printf("Server public key: %v\n", rb.ServerPublicKey)
	fmt.Printf("Censorship record\n")
	fmt.Printf("  Token      : %v\n", rb.Record.CensorshipRecord.Token)
	fmt.Printf("  Merkle root: %v\n", rb.Record.CensorshipRecord.Merkle)
	fmt.Printf("  Signature  : %v\n", rb.Record.CensorshipRecord.Signature)

	err = client.RecordVerify(rb.Record, rb.ServerPublicKey)
	if err != nil {
		return fmt.Errorf("could not verify record: %v", err)
	}

	fmt.Printf("Censorship record verified!\n")
	fmt.Printf("\n")

	// Verify user metadata
	um, err := client.UserMetadataDecode(rb.Record.Metadata)
	if err != nil {
		return err
	}

	fmt.Printf("Author metadata\n")
	fmt.Printf("  ID        : %v\n", um.UserID)
	fmt.Printf("  Public key: %v\n", um.PublicKey)
	fmt.Printf("  Signature : %v\n", um.Signature)

	err = client.UserMetadataVerify(*um, rb.Record.CensorshipRecord.Merkle)
	if err != nil {
		return err
	}

	fmt.Printf("Author signature verified!\n")
	fmt.Printf("\n")

	// Verify status change signatures
	schanges, err := client.StatusChangesDecode(rb.Record.Metadata)
	if err != nil {
		return err
	}
	if len(schanges) == 0 {
		// No status changes have occured. We're done.
		return nil
	}

	for _, v := range schanges {
		fmt.Printf("Status change: %v\n", rcv1.RecordStatuses[v.Status])
		if v.Reason != "" {
			fmt.Printf("  Reason     : %v\n", v.Reason)
		}
		fmt.Printf("  Public key : %v\n", v.PublicKey)
		fmt.Printf("  Signature  : %v\n", v.Signature)
	}

	err = client.StatusChangesVerify(schanges)
	if err != nil {
		return err
	}

	fmt.Printf("Status change signatures verified!\n")

	return nil
}

// verifyRecordTimestamps takes the filepath of record timestamps and verifies
// the validity of all timestamps included in the records v1 TimestampsReply.
func verifyRecordTimestamps(fp string) error {
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
	if tr.RecordMetadata.TxID == "" {
		return fmt.Errorf("data not anchored yet")
	}

	// Pull the token out of the record metadata
	var rm backend.RecordMetadata
	err = json.Unmarshal([]byte(tr.RecordMetadata.Data), &rm)
	if err != nil {
		return fmt.Errorf("could not unmarshal record metadata: %v", err)
	}

	fmt.Printf("Token      : %v\n", rm.Token)
	fmt.Printf("Merkle root: %v\n", tr.RecordMetadata.MerkleRoot)
	fmt.Printf("DCR tx     : %v\n", tr.RecordMetadata.TxID)
	fmt.Printf("Record contents\n")
	fmt.Printf("  Metadata\n")
	for mdID, streams := range tr.Metadata {
		for streamID := range streams {
			fmt.Printf("    %v %v\n", mdID, streamID)
		}
	}
	fmt.Printf("  Files\n")
	for fn := range tr.Files {
		fmt.Printf("    %v\n", fn)
	}

	// Verify timestamps
	err = client.RecordTimestampsVerify(tr)
	if err != nil {
		return err
	}

	fmt.Printf("Record timestamps verified!\n")
	fmt.Printf("The merkle root can be found in the OP_RETURN of the DCR tx.\n")

	return nil
}
