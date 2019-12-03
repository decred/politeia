// Copyright (c) 2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mdstream

import (
	"encoding/json"
	"io"
	"strings"

	pd "github.com/decred/politeia/politeiad/api/v1"
	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
)

// XXX move remaining mdstreams out of politeiawww and into this package
const (
	// mdstream IDs
	IDProposalGeneral      = 0
	IDRecordStatusChange   = 2
	IDInvoiceGeneral       = 3
	IDInvoiceStatusChange  = 4
	IDInvoicePayment       = 5
	IDDCCGeneral           = 6
	IDDCCStatusChange      = 7
	IDDCCSupportOpposition = 8

	// Note that 13 is in use by the decred plugin
	// Note that 14 is in use by the decred plugin
	// Note that 15 is in use by the decred plugin

	// mdstream current supported versions
	VersionProposalGeneral      = 1
	VersionRecordStatusChange   = 1
	VersionInvoiceGeneral       = 1
	VersionInvoiceStatusChange  = 1
	VersionInvoicePayment       = 1
	VersionDCCGeneral           = 1
	VersionDCCStatusChange      = 1
	VersionDCCSupposeOpposition = 1
)

// ProposalGeneral represents general metadata for a proposal.
type ProposalGeneral struct {
	Version   uint64 `json:"version"`   // Struct version
	Timestamp int64  `json:"timestamp"` // Last update of proposal
	Name      string `json:"name"`      // Provided proposal name
	PublicKey string `json:"publickey"` // Key used for signature
	Signature string `json:"signature"` // Signature of proposal files merkle root
}

// EncodeProposalGeneral encodes a ProposalGeneral into a JSON byte slice.
func EncodeProposalGeneral(md ProposalGeneral) ([]byte, error) {
	b, err := json.Marshal(md)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// DecodeProposalGeneral decodes a JSON byte slice into a ProposalGeneral.
func DecodeProposalGeneral(payload []byte) (*ProposalGeneral, error) {
	var md ProposalGeneral
	err := json.Unmarshal(payload, &md)
	if err != nil {
		return nil, err
	}
	return &md, nil
}

// RecordStatusChange represents a politeiad record status change and is used
// to store additional status change metadata that would not otherwise be
// captured by the politeiad status change routes.
//
// This mdstream is used by both pi and cms.
// XXX this is missing the admin signature
type RecordStatusChange struct {
	Version             uint             `json:"version"`                       // Version of the struct
	AdminPubKey         string           `json:"adminpubkey"`                   // Identity of the administrator
	NewStatus           pd.RecordStatusT `json:"newstatus"`                     // New status
	StatusChangeMessage string           `json:"statuschangemessage,omitempty"` // Status change message
	Timestamp           int64            `json:"timestamp"`                     // Timestamp of the change
}

// EncodeRecordStatusChange encodes an RecordStatusChange into a JSON byte
// slice.
func EncodeRecordStatusChange(rsc RecordStatusChange) ([]byte, error) {
	b, err := json.Marshal(rsc)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// DecodeRecordStatusChange decodes a JSON byte slice into a slice of
// RecordStatusChange.
func DecodeRecordStatusChange(payload []byte) ([]RecordStatusChange, error) {
	var changes []RecordStatusChange
	d := json.NewDecoder(strings.NewReader(string(payload)))
	for {
		var rsc RecordStatusChange
		err := d.Decode(&rsc)
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		changes = append(changes, rsc)
	}
	return changes, nil
}

// InvoiceGeneral represents the general metadata for an invoice and is
// stored in the metadata IDInvoiceGeneral in politeiad.
type InvoiceGeneral struct {
	Version   uint64 `json:"version"`   // Version of the struct
	Timestamp int64  `json:"timestamp"` // Last update of invoice
	PublicKey string `json:"publickey"` // Key used for signature
	Signature string `json:"signature"` // Signature of merkle root
}

// EncodeInvoiceGeneral encodes a InvoiceGeneral into a JSON
// byte slice.
func EncodeInvoiceGeneral(md InvoiceGeneral) ([]byte, error) {
	b, err := json.Marshal(md)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// DecodeInvoiceGeneral decodes a JSON byte slice into an InvoiceGeneral.
func DecodeInvoiceGeneral(payload []byte) (*InvoiceGeneral, error) {
	var md InvoiceGeneral

	err := json.Unmarshal(payload, &md)
	if err != nil {
		return nil, err
	}

	return &md, nil
}

// InvoiceStatusChange represents an invoice status change and is stored
// in the metadata IDInvoiceStatusChange in politeiad.
type InvoiceStatusChange struct {
	Version        uint               `json:"version"`        // Version of the struct
	AdminPublicKey string             `json:"adminpublickey"` // Identity of the administrator
	NewStatus      cms.InvoiceStatusT `json:"newstatus"`      // Status
	Reason         string             `json:"reason"`         // Reason
	Timestamp      int64              `json:"timestamp"`      // Timestamp of the change
}

// EncodeInvoiceStatusChange encodes a InvoiceStatusChange into a
// JSON byte slice.
func EncodeInvoiceStatusChange(md InvoiceStatusChange) ([]byte, error) {
	b, err := json.Marshal(md)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// DecodeInvoiceStatusChange decodes a JSON byte slice into a slice of
// InvoiceStatusChanges.
func DecodeInvoiceStatusChange(payload []byte) ([]InvoiceStatusChange, error) {
	var md []InvoiceStatusChange

	d := json.NewDecoder(strings.NewReader(string(payload)))
	for {
		var m InvoiceStatusChange
		err := d.Decode(&m)
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		md = append(md, m)
	}

	return md, nil
}

// InvoicePayment represents an invoice payment and is stored
// in the metadata IDInvoicePayment in politeiad.
type InvoicePayment struct {
	Version        uint   `json:"version"`        // Version of the struct
	TxIDs          string `json:"txids"`          // TxIDs captured from the payment, separated by commas
	Timestamp      int64  `json:"timeupdated"`    // Time of last payment update
	AmountReceived int64  `json:"amountreceived"` // Amount of DCR payment currently received
}

// EncodeInvoicePayment encodes a InvoicePayment into a JSON byte slice.
func EncodeInvoicePayment(md InvoicePayment) ([]byte, error) {
	b, err := json.Marshal(md)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// DecodeInvoicePayment decodes a JSON byte slice into an InvoicePayment.
func DecodeInvoicePayment(payload []byte) ([]InvoicePayment, error) {
	var md []InvoicePayment

	d := json.NewDecoder(strings.NewReader(string(payload)))
	for {
		var m InvoicePayment
		err := d.Decode(&m)
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		md = append(md, m)
	}

	return md, nil
}

// DCCGeneral represents the general metadata for a DCC and is
// stored in the metadata stream IDDCCGeneral in politeiad.
type DCCGeneral struct {
	Version   uint64 `json:"version"`   // Version of the struct
	Timestamp int64  `json:"timestamp"` // Last update of invoice
	PublicKey string `json:"publickey"` // Key used for signature
	Signature string `json:"signature"` // Signature of merkle root
}

// EncodeDCCGeneral encodes a DCCGeneral into a JSON
// byte slice.
func EncodeDCCGeneral(md DCCGeneral) ([]byte, error) {
	b, err := json.Marshal(md)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// DecodeDCCGeneral decodes a JSON byte slice into a
// DCCGeneral.
func DecodeDCCGeneral(payload []byte) (*DCCGeneral, error) {
	var md DCCGeneral

	err := json.Unmarshal(payload, &md)
	if err != nil {
		return nil, err
	}

	return &md, nil
}

// DCCStatusChange represents the metadata for any status change that
// occurs to a patricular DCC issuance or revocation.
type DCCStatusChange struct {
	Version        uint           `json:"version"`        // Version of the struct
	AdminPublicKey string         `json:"adminpublickey"` // Identity of the administrator
	NewStatus      cms.DCCStatusT `json:"newstatus"`      // Status
	Reason         string         `json:"reason"`         // Reason
	Timestamp      int64          `json:"timestamp"`      // Timestamp of the change
	Signature      string         `json:"signature"`      // Signature of Token + NewStatus + Reason
}

// EncodeDCCStatusChange encodes a DCCStatusChange into a
// JSON byte slice.
func EncodeDCCStatusChange(md DCCStatusChange) ([]byte, error) {
	b, err := json.Marshal(md)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// DecodeDCCStatusChange decodes a JSON byte slice into a slice of
// DCCStatusChange.
func DecodeDCCStatusChange(payload []byte) ([]DCCStatusChange, error) {
	var md []DCCStatusChange

	d := json.NewDecoder(strings.NewReader(string(payload)))
	for {
		var m DCCStatusChange
		err := d.Decode(&m)
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		md = append(md, m)
	}

	return md, nil
}

// DCCSupportOpposition represents the general metadata for a DCC
// Support/Opposition 'vote' for a given DCC proposal.
type DCCSupportOpposition struct {
	Version   uint64 `json:"version"`   // Version of the struct
	Timestamp int64  `json:"timestamp"` // Last update of invoice
	PublicKey string `json:"publickey"` // Key used for signature
	Vote      string `json:"vote"`      // Vote for support/opposition
	Signature string `json:"signature"` // Signature of Token + Vote
}

// EncodeDCCSupportOpposition encodes a DCCSupportOpposition into a JSON
// byte slice.
func EncodeDCCSupportOpposition(md DCCSupportOpposition) ([]byte, error) {
	b, err := json.Marshal(md)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// DecodeDCCSupportOpposition decodes a JSON byte slice into a
// DCCSupportOpposition.
func DecodeDCCSupportOpposition(payload []byte) ([]DCCSupportOpposition, error) {
	var md []DCCSupportOpposition

	d := json.NewDecoder(strings.NewReader(string(payload)))
	for {
		var m DCCSupportOpposition
		err := d.Decode(&m)
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		md = append(md, m)
	}

	return md, nil
}
