// Copyright (c) 2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mdstream

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	pd "github.com/thi4go/politeia/politeiad/api/v1"
	"github.com/thi4go/politeia/politeiad/api/v1/identity"
	cms "github.com/thi4go/politeia/politeiawww/api/cms/v1"
	"github.com/thi4go/politeia/util"
)

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
	VersionRecordStatusChange   = 2
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

// RecordStatusChangeV1 represents a politeiad record status change and is used
// to store additional status change metadata that would not otherwise be
// captured by the politeiad status change routes.
//
// This mdstream is used by both pi and cms.
type RecordStatusChangeV1 struct {
	Version             uint             `json:"version"`                       // Version of the struct
	AdminPubKey         string           `json:"adminpubkey"`                   // Identity of the administrator
	NewStatus           pd.RecordStatusT `json:"newstatus"`                     // New status
	StatusChangeMessage string           `json:"statuschangemessage,omitempty"` // Change message
	Timestamp           int64            `json:"timestamp"`                     // UNIX timestamp
}

// EncodeRecordStatusChangeV1 encodes an RecordStatusChangeV1 into a JSON byte
// slice.
func EncodeRecordStatusChangeV1(rsc RecordStatusChangeV1) ([]byte, error) {
	b, err := json.Marshal(rsc)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// RecordStatusChangeV2 represents a politeiad record status change and is used
// to store additional status change metadata that would not otherwise be
// captured by the politeiad status change routes.
//
// V2 adds the Signature field, which was erroneously left out of V1.
//
// This mdstream is used by both pi and cms.
type RecordStatusChangeV2 struct {
	Version             uint             `json:"version"`                       // Struct version
	NewStatus           pd.RecordStatusT `json:"newstatus"`                     // New status
	StatusChangeMessage string           `json:"statuschangemessage,omitempty"` // Change message
	Signature           string           `json:"signature"`                     // Signature of (Token + NewStatus + StatusChangeMessage)
	AdminPubKey         string           `json:"adminpubkey"`                   // Signature pubkey
	Timestamp           int64            `json:"timestamp"`                     // UNIX timestamp
}

// VerifySignature verifies that the RecordStatusChangeV2 signature is correct.
func (r *RecordStatusChangeV2) VerifySignature(token string) error {
	sig, err := util.ConvertSignature(r.Signature)
	if err != nil {
		return err
	}
	b, err := hex.DecodeString(r.AdminPubKey)
	if err != nil {
		return err
	}
	pk, err := identity.PublicIdentityFromBytes(b)
	if err != nil {
		return err
	}
	msg := token + strconv.Itoa(int(r.NewStatus)) + r.StatusChangeMessage
	if !pk.VerifyMessage([]byte(msg), sig) {
		return fmt.Errorf("invalid signature")
	}
	return nil
}

// EncodeRecordStatusChangeV2 encodes an RecordStatusChangeV2 into a JSON byte
// slice.
func EncodeRecordStatusChangeV2(rsc RecordStatusChangeV2) ([]byte, error) {
	b, err := json.Marshal(rsc)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// DecodeRecordStatusChanges decodes a JSON byte slice into a slice of
// RecordStatusChangeV1 and a slice of RecordStatusChangeV2.
func DecodeRecordStatusChanges(payload []byte) ([]RecordStatusChangeV1, []RecordStatusChangeV2, error) {
	statusesV1 := make([]RecordStatusChangeV1, 0, 16)
	statusesV2 := make([]RecordStatusChangeV2, 0, 16)

	d := json.NewDecoder(strings.NewReader(string(payload)))
	for {
		// Decode json into a map so we can determine the version.
		statusChange := make(map[string]interface{}, 6)
		err := d.Decode(&statusChange)
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, nil, err
		}

		// These fields exist in all status change versions so they
		// can be converted to their appropriate types outside the
		// switch statement.
		// Note: a JSON number has to first be type cast to float64
		var (
			version   = uint(statusChange["version"].(float64))
			newStatus = pd.RecordStatusT(int(statusChange["newstatus"].(float64)))
			pubkey    = statusChange["adminpubkey"].(string)
			ts        = int64(statusChange["timestamp"].(float64))
		)

		// The status change message is optional
		var msg string
		m, ok := statusChange["statuschangemessage"]
		if ok {
			msg = m.(string)
		}

		// Handle different versions
		switch version {
		case 1:
			statusesV1 = append(statusesV1, RecordStatusChangeV1{
				Version:             version,
				NewStatus:           newStatus,
				StatusChangeMessage: msg,
				AdminPubKey:         pubkey,
				Timestamp:           ts,
			})
		case 2:
			statusesV2 = append(statusesV2, RecordStatusChangeV2{
				Version:             version,
				NewStatus:           newStatus,
				StatusChangeMessage: msg,
				AdminPubKey:         pubkey,
				Signature:           statusChange["signature"].(string),
				Timestamp:           ts,
			})
		default:
			return nil, nil, fmt.Errorf("invalid status change version: %v",
				statusChange["version"])
		}
	}

	return statusesV1, statusesV2, nil
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
