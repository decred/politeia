// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import "encoding/json"

const (
	Version uint32 = 1
	ID             = "pi"

	// Plugin commands
	CmdLinkedFrom = "linkedfrom" // Get linked from lists

	// Metadata stream IDs. All metadata streams in this plugin will
	// use 1xx numbering.
	MDStreamIDProposalGeneral = 101
	MDStreamIDStatusChange    = 102

	// FilenameProposalMetadata is the filename of the ProposalMetadata
	// file that is saved to politeiad. ProposalMetadata is saved to
	// politeiad as a file, not as a metadata stream, since it needs to
	// be included in the merkle root that politeiad signs.
	FilenameProposalMetadata = "proposalmd.json"
)

// ProposalMetadata contains proposal metadata that is provided by the user on
// proposal submission. ProposalMetadata is saved to politeiad as a file, not
// as a metadata stream, since it needs to be included in the merkle root that
// politeiad signs.
type ProposalMetadata struct {
	// Name is the name of the proposal.
	Name string `json:"name"`

	// LinkTo specifies a public proposal token to link this proposal
	// to. Ex, an RFP sumbssion must link to the RFP proposal.
	LinkTo string `json:"linkto,omitempty"`

	// LinkBy is a UNIX timestamp that serves as a deadline for other
	// proposals to link to this proposal. Ex, an RFP submission cannot
	// link to an RFP proposal once the RFP's LinkBy deadline is past.
	LinkBy int64 `json:"linkby,omitempty"`
}

// ProposalGeneral represents general proposal metadata that is saved on
// proposal submission. ProposalGeneral is saved to politeiad as a metadata
// stream.
//
// Signature is the client signature of the proposal merkle root. The merkle
// root is the ordered merkle root of all proposal Files and Metadata.
type ProposalGeneral struct {
	PublicKey string `json:"publickey"` // Key used for signature
	Signature string `json:"signature"` // Signature of merkle root
	Timestamp int64  `json:"timestamp"` // Submission UNIX timestamp
}

func EncodeProposalGeneral(pg ProposalGeneral) ([]byte, error) {
	return json.Marshal(pg)
}

func DecodeProposalGeneral(payload []byte) (*ProposalGeneral, error) {
	var pg ProposalGeneral
	err := json.Unmarshal(payload, &pg)
	if err != nil {
		return nil, err
	}
	return &pg, nil
}

// StatusChange represents a proposal status change.
//
// Signature is the client signature of the Token+Version+Status+Reason.
type StatusChange struct {
	// Status    PropStatusT `json:"status"`
	Version   string `json:"version"`
	Message   string `json:"message,omitempty"`
	PublicKey string `json:"publickey"`
	Signature string `json:"signature"`
	Timestamp int64  `json:"timestamp"`
}

// LinkedFrom retrieves the linked from list for each of the provided proposal
// tokens. A linked from list is a list of all the proposals that have linked
// to a given proposal using the LinkTo field in the ProposalMetadata mdstream.
// If a token does not correspond to an actual proposal then it will not be
// included in the returned map.
type LinkedFrom struct {
	Tokens []string `json:"tokens"`
}

// EncodeLinkedFrom encodes a LinkedFrom into a JSON byte slice.
func EncodeLinkedFrom(lf LinkedFrom) ([]byte, error) {
	return json.Marshal(lf)
}

// DecodeLinkedFrom decodes a JSON byte slice into a LinkedFrom.
func DecodeLinkedFrom(payload []byte) (*LinkedFrom, error) {
	var lf LinkedFrom
	err := json.Unmarshal(payload, &lf)
	if err != nil {
		return nil, err
	}
	return &lf, nil
}

// LinkedFromReply is the reply to the LinkedFrom command.
type LinkedFromReply struct {
	LinkedFrom map[string][]string `json:"linkedfrom"`
}

// EncodeLinkedFromReply encodes a LinkedFromReply into a JSON byte slice.
func EncodeLinkedFromReply(lfr LinkedFromReply) ([]byte, error) {
	return json.Marshal(lfr)
}

// DecodeLinkedFromReply decodes a JSON byte slice into a LinkedFrom.
func DecodeLinkedFromReply(payload []byte) (*LinkedFromReply, error) {
	var lfr LinkedFromReply
	err := json.Unmarshal(payload, &lfr)
	if err != nil {
		return nil, err
	}
	return &lfr, nil
}
