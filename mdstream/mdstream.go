// Copyright (c) 2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mdstream

import (
	"encoding/json"
	"io"
	"strings"

	pd "github.com/decred/politeia/politeiad/api/v1"
)

// XXX move remaining mdstreams out of politeiawww and into this package
const (
	// Markdown stream IDs
	IDProposalGeneral      = 0
	IDProposalStatusChange = 2
	// Note that 13 is in use by the decred plugin
	// Note that 14 is in use by the decred plugin
	// Note that 15 is in use by the decred plugin
)

// VersionProposalGeneral is the current supported proposal general version.
const VersionProposalGeneral = 1

// ProposalGeneral represents general metadata for a proposal.
type ProposalGeneral struct {
	Version   uint64 `json:"version"`   // Struct version
	Timestamp int64  `json:"timestamp"` // Last update of proposal
	Name      string `json:"name"`      // Generated proposal name
	PublicKey string `json:"publickey"` // Key used for signature
	Signature string `json:"signature"` // Signature of merkle root
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

// VersionProposalStatusChange is the current supported proposal status change
// version.
const VersionProposalStatusChange = 1

// ProposalStatusChange represents a proposal status change.
// XXX this is missing the admin signature
type ProposalStatusChange struct {
	Version             uint             `json:"version"`                       // Version of the struct
	AdminPubKey         string           `json:"adminpubkey"`                   // Identity of the administrator
	NewStatus           pd.RecordStatusT `json:"newstatus"`                     // NewStatus
	StatusChangeMessage string           `json:"statuschangemessage,omitempty"` // Status change message
	Timestamp           int64            `json:"timestamp"`                     // Timestamp of the change
}

// EncodeProposalStatusChange encodes an ProposalStatusChange into a JSON byte
// slice.
func EncodeProposalStatusChange(m ProposalStatusChange) ([]byte, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// DecodeProposalStatusChange decodes a JSON byte slice into a slice of
// ProposalStatusChange.
func DecodeProposalStatusChange(payload []byte) ([]ProposalStatusChange, error) {
	var psc []ProposalStatusChange
	d := json.NewDecoder(strings.NewReader(string(payload)))
	for {
		var p ProposalStatusChange
		err := d.Decode(&p)
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		psc = append(psc, p)
	}
	return psc, nil
}
