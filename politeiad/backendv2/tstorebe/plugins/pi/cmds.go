// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/decred/politeia/util"
)

const (
	pluginID = pi.PluginID

	// Blob entry data descriptors
	dataDescriptorBillingStatus = pluginID + "-billingstatus-v1"
)

// cmdBillingStatus sets record's billing status.
func (p *piPlugin) cmdBillingStatus(token []byte, payload string) (string, error) {
	// Decode payload
	var sbs pi.SetBillingStatus
	err := json.Unmarshal([]byte(payload), &sbs)
	if err != nil {
		return "", err
	}

	// Verify token
	err = tokenMatches(token, sbs.Token)
	if err != nil {
		return "", err
	}

	// Verify signature
	msg := sbs.Token + strconv.FormatUint(uint64(sbs.Status), 10) + sbs.Reason
	err = util.VerifySignature(sbs.Signature, sbs.PublicKey, msg)
	if err != nil {
		return "", convertSignatureError(err)
	}

	// Ensure reason is provided when status is set to closed.
	if sbs.Status == pi.BillingStatusClosed && sbs.Reason == "" {
		return "", backend.PluginError{
			PluginID:  pi.PluginID,
			ErrorCode: uint32(pi.ErrorCodeBillingStatusChangeNotAllowed),
			ErrorContext: "must provide a reason when setting " +
				"billing status to closed",
		}
	}

	// Ensure no billing status already exists
	statuses, err := p.billingStatuses(token)
	if err != nil {
		return "", err
	}
	if len(statuses) > 0 {
		return "", backend.PluginError{
			PluginID:     pi.PluginID,
			ErrorCode:    uint32(pi.ErrorCodeBillingStatusChangeNotAllowed),
			ErrorContext: "can not set billing status more than once",
		}
	}

	// Ensure record's vote ended and it was approved
	vsr, err := p.voteSummary(token)
	if vsr.Status != ticketvote.VoteStatusApproved {
		return "", backend.PluginError{
			PluginID:  pi.PluginID,
			ErrorCode: uint32(pi.ErrorCodeBillingStatusChangeNotAllowed),
			ErrorContext: "setting billing status is allowed only if " +
				"record was approved",
		}
	}

	// Save billing status change
	receipt := p.identity.SignMessage([]byte(sbs.Signature))
	bsc := pi.BillingStatusChange{
		Token:     sbs.Token,
		Status:    sbs.Status,
		Reason:    sbs.Reason,
		PublicKey: sbs.PublicKey,
		Signature: sbs.Signature,
		Timestamp: time.Now().Unix(),
		Receipt:   hex.EncodeToString(receipt[:]),
	}
	err = p.billingStatusSave(token, bsc)
	if err != nil {
		return "", err
	}

	// Prepare reply
	sbsr := pi.SetBillingStatusReply{
		Timestamp: bsc.Timestamp,
		Receipt:   bsc.Receipt,
	}
	reply, err := json.Marshal(sbsr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// billingStatusSave saves a BillingStatusChange to the backend.
func (p *piPlugin) billingStatusSave(token []byte, bsc pi.BillingStatusChange) error {
	// Prepare blob
	be, err := billingStatusEncode(bsc)
	if err != nil {
		return err
	}

	// Save blob
	return p.tstore.BlobSave(token, *be)
}

// billingStatuses returns all BillingStatusChange for a record.
func (p *piPlugin) billingStatuses(token []byte) ([]pi.BillingStatusChange, error) {
	// Retrieve blobs
	blobs, err := p.tstore.BlobsByDataDesc(token,
		[]string{dataDescriptorBillingStatus})
	if err != nil {
		return nil, err
	}

	// Decode blobs
	statuses := make([]pi.BillingStatusChange, 0, len(blobs))
	for _, v := range blobs {
		a, err := billingStatusDecode(v)
		if err != nil {
			return nil, err
		}
		statuses = append(statuses, *a)
	}

	// Sanity check. They should already be sorted from oldest to
	// newest.
	sort.SliceStable(statuses, func(i, j int) bool {
		return statuses[i].Timestamp < statuses[j].Timestamp
	})

	return statuses, nil
}

// tokenMatches verifies that the command token (the token for the record that
// this plugin command is being executed on) matches the payload token (the
// token that the plugin command payload contains that is typically used in the
// payload signature). The payload token must be the full length token.
func tokenMatches(cmdToken []byte, payloadToken string) error {
	pt, err := tokenDecode(payloadToken)
	if err != nil {
		return backend.PluginError{
			PluginID:     pi.PluginID,
			ErrorCode:    uint32(pi.ErrorCodeTokenInvalid),
			ErrorContext: util.TokenRegexp(),
		}
	}
	if !bytes.Equal(cmdToken, pt) {
		return backend.PluginError{
			PluginID:  pi.PluginID,
			ErrorCode: uint32(pi.ErrorCodeTokenInvalid),
			ErrorContext: fmt.Sprintf("payload token does not "+
				"match command token: got %x, want %x",
				pt, cmdToken),
		}
	}
	return nil
}

// convertSignatureError converts a util SignatureError to a backend
// PluginError that contains a pi plugin error code.
func convertSignatureError(err error) backend.PluginError {
	var e util.SignatureError
	var s pi.ErrorCodeT
	if errors.As(err, &e) {
		switch e.ErrorCode {
		case util.ErrorStatusPublicKeyInvalid:
			s = pi.ErrorCodePublicKeyInvalid
		case util.ErrorStatusSignatureInvalid:
			s = pi.ErrorCodeSignatureInvalid
		}
	}
	return backend.PluginError{
		PluginID:     pi.PluginID,
		ErrorCode:    uint32(s),
		ErrorContext: e.ErrorContext,
	}
}

func billingStatusEncode(bsc pi.BillingStatusChange) (*store.BlobEntry, error) {
	data, err := json.Marshal(bsc)
	if err != nil {
		return nil, err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: dataDescriptorBillingStatus,
		})
	if err != nil {
		return nil, err
	}
	be := store.NewBlobEntry(hint, data)
	return &be, nil
}

func billingStatusDecode(be store.BlobEntry) (*pi.BillingStatusChange, error) {
	// Decode and validate data hint
	b, err := base64.StdEncoding.DecodeString(be.DataHint)
	if err != nil {
		return nil, fmt.Errorf("decode DataHint: %v", err)
	}
	var dd store.DataDescriptor
	err = json.Unmarshal(b, &dd)
	if err != nil {
		return nil, fmt.Errorf("unmarshal DataHint: %v", err)
	}
	if dd.Descriptor != dataDescriptorBillingStatus {
		return nil, fmt.Errorf("unexpected data descriptor: got %v, "+
			"want %v", dd.Descriptor, dataDescriptorBillingStatus)
	}

	// Decode data
	b, err = base64.StdEncoding.DecodeString(be.Data)
	if err != nil {
		return nil, fmt.Errorf("decode Data: %v", err)
	}
	digest, err := hex.DecodeString(be.Digest)
	if err != nil {
		return nil, fmt.Errorf("decode digest: %v", err)
	}
	if !bytes.Equal(util.Digest(b), digest) {
		return nil, fmt.Errorf("data is not coherent; got %x, want %x",
			util.Digest(b), digest)
	}
	var bsc pi.BillingStatusChange
	err = json.Unmarshal(b, &bsc)
	if err != nil {
		return nil, fmt.Errorf("unmarshal AuthDetails: %v", err)
	}

	return &bsc, nil
}
