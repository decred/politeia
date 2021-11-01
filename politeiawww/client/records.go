// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package client

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/decred/politeia/politeiad/api/v1/identity"
	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/plugins/usermd"
	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	v1 "github.com/decred/politeia/politeiawww/api/records/v1"
	"github.com/decred/politeia/util"
	"github.com/google/uuid"
)

// RecordPolicy sends a records v1 Policy request to politeiawww.
func (c *Client) RecordPolicy() (*rcv1.PolicyReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		rcv1.APIRoute, rcv1.RoutePolicy, nil)
	if err != nil {
		return nil, err
	}

	var pr rcv1.PolicyReply
	err = json.Unmarshal(resBody, &pr)
	if err != nil {
		return nil, err
	}

	return &pr, nil
}

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

	return &dr.Record, nil
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

	return &tr, nil
}

// Records sends a records v1 Records request to politeiawww.
func (c *Client) Records(r rcv1.Records) (map[string]rcv1.Record, error) {
	resBody, err := c.makeReq(http.MethodPost,
		rcv1.APIRoute, rcv1.RouteRecords, r)
	if err != nil {
		return nil, err
	}

	var rr rcv1.RecordsReply
	err = json.Unmarshal(resBody, &rr)
	if err != nil {
		return nil, err
	}

	return rr.Records, nil
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

	return &ir, nil
}

// RecordInventoryOrdered sends a records v1 InventoryOrdered request to
// politeiawww.
func (c *Client) RecordInventoryOrdered(i rcv1.InventoryOrdered) (*rcv1.InventoryOrderedReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		rcv1.APIRoute, rcv1.RouteInventoryOrdered, i)
	if err != nil {
		return nil, err
	}

	var ir rcv1.InventoryOrderedReply
	err = json.Unmarshal(resBody, &ir)
	if err != nil {
		return nil, err
	}

	return &ir, nil
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

// CensorshipRecordVerify verifies the censorship record of a records v1
// Record.
func CensorshipRecordVerify(r rcv1.Record, serverPubKey string) error {
	if r.Status == rcv1.RecordStatusCensored {
		// The files of a censored record will be deleted.
		// There is nothing to verify.
		return nil
	}

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
	id, err := identity.PublicIdentityFromString(serverPubKey)
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

// RecordVerify verfifies the contents of a record. This includes verifying
// the censorship record, the user metadata, and any status changes that are
// present.
//
// **Note** partial record's merkle root is not verifiable - when generating
// the record's merkle all files must be present.
func RecordVerify(r rcv1.Record, serverPubKey string) error {
	// Verify censorship record
	err := CensorshipRecordVerify(r, serverPubKey)
	if err != nil {
		return fmt.Errorf("verify censorship record: %v", err)
	}

	// Verify user metadata
	um, err := UserMetadataDecode(r.Metadata)
	if err != nil {
		return err
	}
	err = UserMetadataVerify(*um, r.CensorshipRecord.Merkle)
	if err != nil {
		return fmt.Errorf("verify user metadata: %v", err)
	}

	// Verify status changes
	sc, err := StatusChangesDecode(r.Metadata)
	if err != nil {
		return err
	}
	err = StatusChangesVerify(sc)
	if err != nil {
		return fmt.Errorf("verify status changes: %v", err)
	}

	return nil
}

// RecordTimestampVerify verifies a records v1 API timestamp. This proves
// inclusion of the data in the merkle root that was timestamped onto the dcr
// blockchain.
func RecordTimestampVerify(t rcv1.Timestamp) error {
	return backend.VerifyTimestamp(convertRecordTimestamp(t))
}

// RecordTimestampsVerify verifies all timestamps in a records v1 API
// timestamps reply. This proves the inclusion of the data in the merkle root
// that was timestamped onto the dcr blockchain.
func RecordTimestampsVerify(tr rcv1.TimestampsReply) error {
	err := RecordTimestampVerify(tr.RecordMetadata)
	if err != nil {
		return fmt.Errorf("could not verify record metadata timestamp: %v", err)
	}
	for pluginID, v := range tr.Metadata {
		for streamID, ts := range v {
			err = RecordTimestampVerify(ts)
			if err != nil {
				return fmt.Errorf("could not verify metadata %v %v timestamp: %v",
					pluginID, streamID, err)
			}
		}
	}
	for k, v := range tr.Files {
		err = RecordTimestampVerify(v)
		if err != nil {
			return fmt.Errorf("could not verify file %v timestamp: %v", k, err)
		}
	}
	return nil
}

// UserMetadataDecode decodes and returns the UserMetadata from the provided
// metadata streams. An error is returned if a UserMetadata is not found.
func UserMetadataDecode(ms []v1.MetadataStream) (*rcv1.UserMetadata, error) {
	var ump *rcv1.UserMetadata
	for _, v := range ms {
		if v.PluginID != usermd.PluginID ||
			v.StreamID != usermd.StreamIDUserMetadata {
			// Not user metadata
			continue
		}
		var um rcv1.UserMetadata
		err := json.Unmarshal([]byte(v.Payload), &um)
		if err != nil {
			return nil, err
		}
		ump = &um
		break
	}
	if ump == nil {
		return nil, fmt.Errorf("user metadata not found")
	}
	return ump, nil
}

// UserMetadataVerify verifies that the UserMetadata contains a valid user ID,
// a valid public key, and that this signature is a valid signature of the
// record merkle root.
func UserMetadataVerify(um v1.UserMetadata, merkleRoot string) error {
	// Verify user ID
	_, err := uuid.Parse(um.UserID)
	if err != nil {
		return fmt.Errorf("invalid user id: %v", err)
	}

	// Verify signature
	err = util.VerifySignature(um.Signature, um.PublicKey, merkleRoot)
	if err != nil {
		return fmt.Errorf("invalid user metadata: %v", err)
	}

	return nil
}

// StatusChangesDecode decodes and returns the status changes metadata stream
// from the provided metadata. An error IS NOT returned is status change
// metadata is not found.
func StatusChangesDecode(metadata []v1.MetadataStream) ([]v1.StatusChange, error) {
	statuses := make([]v1.StatusChange, 0, 16)
	for _, v := range metadata {
		if v.PluginID != usermd.PluginID ||
			v.StreamID != usermd.StreamIDStatusChanges {
			// Not status change metadata
			continue
		}
		d := json.NewDecoder(strings.NewReader(v.Payload))
		for {
			var sc v1.StatusChange
			err := d.Decode(&sc)
			if errors.Is(err, io.EOF) {
				break
			} else if err != nil {
				return nil, err
			}
			statuses = append(statuses, sc)
		}
		break
	}
	return statuses, nil
}

// StatusChanges verifies the signatures on all status change metadata.
func StatusChangesVerify(sc []v1.StatusChange) error {
	// Verify signatures
	for _, v := range sc {
		var (
			status  = strconv.FormatUint(uint64(v.Status), 10)
			version = strconv.FormatUint(uint64(v.Version), 10)
			msg     = v.Token + version + status + v.Reason
		)
		err := util.VerifySignature(v.Signature, v.PublicKey, msg)
		if err != nil {
			return fmt.Errorf("invalid status change signature %v %v: %v",
				v.Token, v1.RecordStatuses[v.Status], err)
		}
	}

	return nil
}

func convertRecordProof(p rcv1.Proof) backend.Proof {
	return backend.Proof{
		Type:       p.Type,
		Digest:     p.Digest,
		MerkleRoot: p.MerkleRoot,
		MerklePath: p.MerklePath,
		ExtraData:  p.ExtraData,
	}
}

func convertRecordTimestamp(t rcv1.Timestamp) backend.Timestamp {
	proofs := make([]backend.Proof, 0, len(t.Proofs))
	for _, v := range t.Proofs {
		proofs = append(proofs, convertRecordProof(v))
	}
	return backend.Timestamp{
		Data:       t.Data,
		Digest:     t.Digest,
		TxID:       t.TxID,
		MerkleRoot: t.MerkleRoot,
		Proofs:     proofs,
	}
}
