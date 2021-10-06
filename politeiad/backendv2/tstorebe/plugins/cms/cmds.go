// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cms

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/pkg/errors"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/decred/politeia/politeiad/plugins/cms"
	"github.com/decred/politeia/politeiad/plugins/usermd"
	"github.com/decred/politeia/util"
)

const (
	pluginID = cms.PluginID

	// Blob entry data descriptors
	dataDescriptorInvoiceStatus = pluginID + "-invoicestatus-v1"
)

// cmdSetInvoiceStatus sets invoice's invoice status.
func (c *cmsPlugin) cmdSetInvoiceStatus(token []byte, payload string) (string, error) {
	// Decode payload
	var sbs cms.SetInvoiceStatus
	err := json.Unmarshal([]byte(payload), &sbs)
	if err != nil {
		return "", err
	}

	// Verify token
	err = tokenMatches(token, sbs.Token)
	if err != nil {
		return "", err
	}

	// Verify invoice status
	switch sbs.Status {
	case cms.InvoiceStatusApproved, cms.InvoiceStatusDisputed,
		cms.InvoiceStatusNew, cms.InvoiceStatusNotFound, cms.InvoiceStatusPaid,
		cms.InvoiceStatusRejected, cms.InvoiceStatusUpdated:
	default:
		// Invoice status is invalid
		return "", backend.PluginError{
			PluginID:     cms.PluginID,
			ErrorCode:    uint32(cms.ErrorCodeInvoiceStatusInvalid),
			ErrorContext: "invalid invoice status",
		}
	}

	// Verify signature
	msg := sbs.Token + string(sbs.Status) + sbs.Reason
	err = util.VerifySignature(sbs.Signature, sbs.PublicKey, msg)
	if err != nil {
		return "", convertSignatureError(err)
	}

	// Ensure reason is provided when status is set to closed.
	if sbs.Status == cms.InvoiceStatusRejected && sbs.Reason == "" {
		return "", backend.PluginError{
			PluginID:  cms.PluginID,
			ErrorCode: uint32(cms.ErrorCodeInvoiceStatusChangeNotAllowed),
			ErrorContext: "must provide a reason when setting " +
				"invoice status to rejected",
		}
	}

	// Ensure no invoice status already exists
	bscs, err := c.invoiceStatusChanges(token)
	if err != nil {
		return "", err
	}

	// CHECK TO SEE IF THE PREVIOUSLY SET STATUS ALLOWS TO BE SET TO REQUESTED
	switch bscs[len(bscs)-1].Status {
	case cms.InvoiceStatusNew, cms.InvoiceStatusUpdated, cms.InvoiceStatusDisputed:
		// These statuses allow for any updating.
	case cms.InvoiceStatusApproved:
		// Should we allow for the status to be updated if it was set to approved already?
	case cms.InvoiceStatusPaid, cms.InvoiceStatusRejected:
		return "", backend.PluginError{
			PluginID:     cms.PluginID,
			ErrorCode:    uint32(cms.ErrorCodeInvoiceStatusChangeNotAllowed),
			ErrorContext: "can not set invoice status more than once",
		}
	}

	// Save invoice status change
	receipt := c.identity.SignMessage([]byte(sbs.Signature))
	bsc := cms.InvoiceStatusChange{
		Token:     sbs.Token,
		Status:    sbs.Status,
		Reason:    sbs.Reason,
		PublicKey: sbs.PublicKey,
		Signature: sbs.Signature,
		Timestamp: time.Now().Unix(),
		Receipt:   hex.EncodeToString(receipt[:]),
	}
	err = c.invoiceStatusSave(token, bsc)
	if err != nil {
		return "", err
	}

	// Prepare reply
	sbsr := cms.SetInvoiceStatusReply{
		Timestamp: bsc.Timestamp,
		Receipt:   bsc.Receipt,
	}
	reply, err := json.Marshal(sbsr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// tokenMatches verifies that the command token (the token for the record that
// this plugin command is being executed on) matches the payload token (the
// token that the plugin command payload contains that is typically used in the
// payload signature). The payload token must be the full length token.
func tokenMatches(cmdToken []byte, payloadToken string) error {
	pt, err := tokenDecode(payloadToken)
	if err != nil {
		return backend.PluginError{
			PluginID:     cms.PluginID,
			ErrorCode:    uint32(cms.ErrorCodeTokenInvalid),
			ErrorContext: util.TokenRegexp(),
		}
	}
	if !bytes.Equal(cmdToken, pt) {
		return backend.PluginError{
			PluginID:  cms.PluginID,
			ErrorCode: uint32(cms.ErrorCodeTokenInvalid),
			ErrorContext: fmt.Sprintf("payload token does not "+
				"match command token: got %x, want %x",
				pt, cmdToken),
		}
	}
	return nil
}

// cmdSummary returns the cms summary of a invoice.
func (c *cmsPlugin) cmdSummary(token []byte) (string, error) {
	// Get record metadata
	r, err := c.recordAbridged(token)
	if err != nil {
		return "", err
	}
	var (
		mdState  = r.RecordMetadata.State
		mdStatus = r.RecordMetadata.Status

		bsc *cms.InvoiceStatusChange
	)

	invoiceStatus, err := invoiceStatus(mdState, mdStatus, bsc)
	if err != nil {
		return "", err
	}

	// Prepare reply
	sr := cms.SummaryReply{
		Summary: cms.InvoiceSummary{
			Status: invoiceStatus,
		},
	}
	reply, err := json.Marshal(sr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// cmdInvoiceStatusChanges returns the invoice status changes of a invoice.
func (c *cmsPlugin) cmdInvoiceStatusChanges(token []byte) (string, error) {
	// Get invoice status changes
	bscs, err := c.invoiceStatusChanges(token)
	if err != nil {
		return "", err
	}

	// Prepare reply
	bscsr := cms.InvoiceStatusChangesReply{
		InvoiceStatusChanges: bscs,
	}
	reply, err := json.Marshal(bscsr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// statusChangesDecode decodes and returns the StatusChangeMetadata from the
// metadata streams if one is present.
func statusChangesDecode(metadata []backend.MetadataStream) ([]usermd.StatusChangeMetadata, error) {
	statuses := make([]usermd.StatusChangeMetadata, 0, 16)
	for _, v := range metadata {
		if v.PluginID != usermd.PluginID ||
			v.StreamID != usermd.StreamIDStatusChanges {
			// Not the mdstream we're looking for
			continue
		}
		d := json.NewDecoder(strings.NewReader(v.Payload))
		for {
			var sc usermd.StatusChangeMetadata
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

// invoiceStatus combines record metadata and plugin metadata in order to
// create a unified map of the various paths a invoice can take throughout
// the invoice process.
func invoiceStatus(state backend.StateT, status backend.StatusT, bsc *cms.InvoiceStatusChange) (cms.InvoiceStatusT, error) {
	switch state {
	case backend.StateUnvetted:
		return cms.InvoiceStatusInvalid, nil // Just say invalid, since they shouldn't be here?
	case backend.StateVetted:
		switch status {
		case backend.StatusArchived:
			return cms.InvoiceStatusInvalid, nil // Just say invalid, since they shouldn't be here?
		case backend.StatusCensored:
			return cms.InvoiceStatusInvalid, nil // Just say invalid, since they shouldn't be here?
		case backend.StatusPublic:
			return bsc.Status, nil
		}
	}
	// Shouldn't happen return an error
	return cms.InvoiceStatusInvalid,
		errors.Errorf(
			"couldn't determine invoice status: invoice state: %v, "+
				"invoice status %v", state, status)
}

// recordAbridged returns a record with all files omitted.
func (c *cmsPlugin) recordAbridged(token []byte) (*backend.Record, error) {
	reqs := []backend.RecordRequest{
		{
			Token:        token,
			OmitAllFiles: true,
		},
	}
	rs, err := c.backend.Records(reqs)
	if err != nil {
		return nil, err
	}
	r, ok := rs[hex.EncodeToString(token)]
	if !ok {
		return nil, backend.ErrRecordNotFound
	}

	return &r, nil
}

// convertSignatureError converts a util SignatureError to a backend
// PluginError that contains a cms plugin error code.
func convertSignatureError(err error) backend.PluginError {
	var e util.SignatureError
	var s cms.ErrorCodeT
	if errors.As(err, &e) {
		switch e.ErrorCode {
		case util.ErrorStatusPublicKeyInvalid:
			s = cms.ErrorCodePublicKeyInvalid
		case util.ErrorStatusSignatureInvalid:
			s = cms.ErrorCodeSignatureInvalid
		}
	}
	return backend.PluginError{
		PluginID:     cms.PluginID,
		ErrorCode:    uint32(s),
		ErrorContext: e.ErrorContext,
	}
}

// invoiceStatusSave saves a InvoiceStatusChange to the backend.
func (c *cmsPlugin) invoiceStatusSave(token []byte, bsc cms.InvoiceStatusChange) error {
	// Prepare blob
	be, err := invoiceStatusEncode(bsc)
	if err != nil {
		return err
	}

	// Save blob
	return c.tstore.BlobSave(token, *be)
}

// invoiceStatusChanges returns the invoice status changes of a proposal.
func (c *cmsPlugin) invoiceStatusChanges(token []byte) ([]cms.InvoiceStatusChange, error) {
	// Retrieve blobs
	blobs, err := c.tstore.BlobsByDataDesc(token,
		[]string{dataDescriptorInvoiceStatus})
	if err != nil {
		return nil, err
	}

	// Decode blobs
	statusChanges := make([]cms.InvoiceStatusChange, 0, len(blobs))
	for _, v := range blobs {
		a, err := invoiceStatusDecode(v)
		if err != nil {
			return nil, err
		}
		statusChanges = append(statusChanges, *a)
	}

	// Sanity check. They should already be sorted from oldest to
	// newest.
	sort.SliceStable(statusChanges, func(i, j int) bool {
		return statusChanges[i].Timestamp < statusChanges[j].Timestamp
	})

	return statusChanges, nil
}

// invoiceStatusEncode encodes a InvoiceStatusChange into a BlobEntry.
func invoiceStatusEncode(bsc cms.InvoiceStatusChange) (*store.BlobEntry, error) {
	data, err := json.Marshal(bsc)
	if err != nil {
		return nil, err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: dataDescriptorInvoiceStatus,
		})
	if err != nil {
		return nil, err
	}
	be := store.NewBlobEntry(hint, data)
	return &be, nil
}

// invoiceStatusDecode decodes a BlobEntry into a InvoiceStatusChange.
func invoiceStatusDecode(be store.BlobEntry) (*cms.InvoiceStatusChange, error) {
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
	if dd.Descriptor != dataDescriptorInvoiceStatus {
		return nil, fmt.Errorf("unexpected data descriptor: got %v, "+
			"want %v", dd.Descriptor, dataDescriptorInvoiceStatus)
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
	var bsc cms.InvoiceStatusChange
	err = json.Unmarshal(b, &bsc)
	if err != nil {
		return nil, fmt.Errorf("unmarshal AuthDetails: %v", err)
	}

	return &bsc, nil
}
