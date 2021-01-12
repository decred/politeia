// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package pi provides a politeiad plugin for functionality that is specific to
// decred's proposal system.
package pi

import (
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/decred/politeia/politeiad/plugins/comments"
)

type PropStateT int
type PropStatusT int
type ErrorStatusT int
type CommentVoteT int

const (
	ID = "pi"

	// Plugin commands
	CmdPassThrough   = "passthrough" // Plugin command pass through
	CmdProposalInv   = "proposalinv" // Get inventory by proposal status
	CmdVoteInventory = "voteinv"     // Get inventory by vote status

	// TODO get rid of CmdProposals
	CmdProposals = "proposals" // Get plugin data for proposals

	// Metadata stream IDs
	MDStreamIDGeneralMetadata = 1
	MDStreamIDStatusChanges   = 2

	// FileNameProposalMetadata is the filename of the ProposalMetadata
	// file that is saved to politeiad. ProposalMetadata is saved to
	// politeiad as a file, not as a metadata stream, since it contains
	// user provided metadata and needs to be included in the merkle
	// root that politeiad signs.
	FileNameProposalMetadata = "proposalmetadata.json"

	// Proposal states
	PropStateInvalid  PropStateT = 0
	PropStateUnvetted PropStateT = 1
	PropStateVetted   PropStateT = 2

	// Proposal status codes
	PropStatusInvalid   PropStatusT = 0 // Invalid status
	PropStatusUnvetted  PropStatusT = 1 // Prop has not been vetted
	PropStatusPublic    PropStatusT = 2 // Prop has been made public
	PropStatusCensored  PropStatusT = 3 // Prop has been censored
	PropStatusAbandoned PropStatusT = 4 // Prop has been abandoned

	// User error status codes
	// TODO number error codes and add human readable error messages
	ErrorStatusInvalid          ErrorStatusT = 0
	ErrorStatusPageSizeExceeded ErrorStatusT = iota
	ErrorStatusPropNotFound
	ErrorStatusPropStateInvalid
	ErrorStatusPropTokenInvalid
	ErrorStatusPropStatusInvalid
	ErrorStatusPropVersionInvalid
	ErrorStatusPropStatusChangeInvalid
	ErrorStatusPropLinkToInvalid
	ErrorStatusVoteStatusInvalid
	ErrorStatusStartDetailsInvalid
	ErrorStatusStartDetailsMissing
	ErrorStatusVoteParentInvalid
	ErrorStatusLinkByNotExpired
)

var (
	// PropStatuses contains the human readable proposal statuses.
	PropStatuses = map[PropStatusT]string{
		PropStatusInvalid:   "invalid",
		PropStatusUnvetted:  "unvetted",
		PropStatusPublic:    "public",
		PropStatusCensored:  "censored",
		PropStatusAbandoned: "abandoned",
	}

	// StatusChanges contains the allowed proposal status change
	// transitions. If StatusChanges[currentStatus][newStatus] exists
	// then the status change is allowed.
	StatusChanges = map[PropStatusT]map[PropStatusT]struct{}{
		PropStatusUnvetted: {
			PropStatusPublic:   {},
			PropStatusCensored: {},
		},
		PropStatusPublic: {
			PropStatusAbandoned: {},
			PropStatusCensored:  {},
		},
		PropStatusCensored:  {},
		PropStatusAbandoned: {},
	}
)

// ProposalMetadata contains metadata that is provided by the user as part of
// the proposal submission bundle. The proposal metadata is included in the
// proposal signature since it is user specified data. The ProposalMetadata
// object is saved to politeiad as a file, not as a metadata stream, since it
// needs to be included in the merkle root that politeiad signs.
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

// EncodeProposalMetadata encodes a ProposalMetadata into a JSON byte slice.
func EncodeProposalMetadata(pm ProposalMetadata) ([]byte, error) {
	return json.Marshal(pm)
}

// DecodeProposalMetadata decodes a JSON byte slice into a ProposalMetadata.
func DecodeProposalMetadata(payload []byte) (*ProposalMetadata, error) {
	var pm ProposalMetadata
	err := json.Unmarshal(payload, &pm)
	if err != nil {
		return nil, err
	}
	return &pm, nil
}

// GeneralMetadata contains general metadata about a politeiad record. It is
// saved to politeiad as a metadata stream.
//
// Signature is the client signature of the record merkle root. The merkle root
// is the ordered merkle root of all politeiad Files.
type GeneralMetadata struct {
	UserID    string `json:"userid"`    // Author user ID
	PublicKey string `json:"publickey"` // Key used for signature
	Signature string `json:"signature"` // Signature of merkle root
	Timestamp int64  `json:"timestamp"` // Submission UNIX timestamp
}

// EncodeGeneralMetadata encodes a GeneralMetadata into a JSON byte slice.
func EncodeGeneralMetadata(gm GeneralMetadata) ([]byte, error) {
	return json.Marshal(gm)
}

// DecodeGeneralMetadata decodes a JSON byte slice into a GeneralMetadata.
func DecodeGeneralMetadata(payload []byte) (*GeneralMetadata, error) {
	var gm GeneralMetadata
	err := json.Unmarshal(payload, &gm)
	if err != nil {
		return nil, err
	}
	return &gm, nil
}

// StatusChange represents a proposal status change.
//
// Signature is the client signature of the Token+Version+Status+Reason.
type StatusChange struct {
	Token     string      `json:"token"`
	Version   string      `json:"version"`
	Status    PropStatusT `json:"status"`
	Reason    string      `json:"message,omitempty"`
	PublicKey string      `json:"publickey"`
	Signature string      `json:"signature"`
	Timestamp int64       `json:"timestamp"`
}

// EncodeStatusChange encodes a StatusChange into a JSON byte slice.
func EncodeStatusChange(sc StatusChange) ([]byte, error) {
	return json.Marshal(sc)
}

// DecodeStatusChange decodes a JSON byte slice into a StatusChange.
func DecodeStatusChange(payload []byte) (*StatusChange, error) {
	var sc StatusChange
	err := json.Unmarshal(payload, &sc)
	if err != nil {
		return nil, err
	}
	return &sc, nil
}

// DecodeStatusChanges decodes a JSON byte slice into a []StatusChange.
func DecodeStatusChanges(payload []byte) ([]StatusChange, error) {
	var statuses []StatusChange
	d := json.NewDecoder(strings.NewReader(string(payload)))
	for {
		var sc StatusChange
		err := d.Decode(&sc)
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, err
		}
		statuses = append(statuses, sc)
	}

	return statuses, nil
}

// PassThrough is used to extended a command from a different plugin package
// with functionality that is specific to the pi plugin, without needing to
// define a new pi command and new pi types. The command passes through the pi
// plugin before being executed.
//
// Example, the pi plugin does not allow comments to be made on a proposal if
// the proposal vote has ended. This validation is specific to the pi plugin
// and does not require the comment payloads to be altered. PassThrough is used
// to pass the comments plugin command through the pi plugin, where the pi
// plugin can first perform pi specific validation before executing the
// comments plugin command.
type PassThrough struct {
	PluginID  string `json:"pluginid"`
	PluginCmd string `json:"plugincmd"`
	Payload   string `json:"payload"`
}

// EncodePassThrough encodes a PassThrough into a JSON byte slice.
func EncodePassThrough(p PassThrough) ([]byte, error) {
	return json.Marshal(p)
}

// DecodePassThrough decodes a JSON byte slice into a PassThrough.
func DecodePassThrough(payload []byte) (*PassThrough, error) {
	var p PassThrough
	err := json.Unmarshal(payload, &p)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// PassThroughReply is the reply to the PassThrough command.
type PassThroughReply struct {
	Payload string `json:"payload"`
}

// EncodePassThroughReply encodes a PassThroughReply into a JSON byte slice.
func EncodePassThroughReply(p PassThroughReply) ([]byte, error) {
	return json.Marshal(p)
}

// DecodePassThroughReply decodes a JSON byte slice into a PassThroughReply.
func DecodePassThroughReply(payload []byte) (*PassThroughReply, error) {
	var p PassThroughReply
	err := json.Unmarshal(payload, &p)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// Proposals requests the plugin data for the provided proposals. This includes
// pi plugin data as well as other plugin data such as comment plugin data.
// This command aggregates all proposal plugin data into a single call.
type Proposals struct {
	State  PropStateT `json:"state"`
	Tokens []string   `json:"tokens"`
}

// EncodeProposals encodes a Proposals into a JSON byte slice.
func EncodeProposals(p Proposals) ([]byte, error) {
	return json.Marshal(p)
}

// DecodeProposals decodes a JSON byte slice into a Proposals.
func DecodeProposals(payload []byte) (*Proposals, error) {
	var p Proposals
	err := json.Unmarshal(payload, &p)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// ProposalPluginData contains all the plugin data for a proposal.
type ProposalPluginData struct {
	Comments   uint64   `json:"comments"`   // Number of comments
	LinkedFrom []string `json:"linkedfrom"` // Linked from list
}

// ProposalsReply is the reply to the Proposals command. The proposals map will
// not contain an entry for tokens that do not correspond to actual proposals.
type ProposalsReply struct {
	Proposals map[string]ProposalPluginData `json:"proposals"`
}

// EncodeProposalsReply encodes a ProposalsReply into a JSON byte slice.
func EncodeProposalsReply(pr ProposalsReply) ([]byte, error) {
	return json.Marshal(pr)
}

// DecodeProposalsReply decodes a JSON byte slice into a ProposalsReply.
func DecodeProposalsReply(payload []byte) (*ProposalsReply, error) {
	var pr ProposalsReply
	err := json.Unmarshal(payload, &pr)
	if err != nil {
		return nil, err
	}
	return &pr, nil
}

// CommentNew creates a new comment. This command relies on the comments plugin
// New command, but also performs additional vote status validation that is
// specific to pi.
//
// The parent ID is used to reply to an existing comment. A parent ID of 0
// indicates that the comment is a base level comment and not a reply commment.
//
// Signature is the client signature of State+Token+ParentID+Comment.
type CommentNew struct {
	UserID    string     `json:"userid"`    // Unique user ID
	State     PropStateT `json:"state"`     // Record state
	Token     string     `json:"token"`     // Record token
	ParentID  uint32     `json:"parentid"`  // Parent comment ID
	Comment   string     `json:"comment"`   // Comment text
	PublicKey string     `json:"publickey"` // Pubkey used for Signature
	Signature string     `json:"signature"` // Client signature
}

// EncodeCommentNew encodes a CommentNew into a JSON byte slice.
func EncodeCommentNew(cn CommentNew) ([]byte, error) {
	return json.Marshal(cn)
}

// DecodeCommentNew decodes a JSON byte slice into a CommentNew.
func DecodeCommentNew(payload []byte) (*CommentNew, error) {
	var cn CommentNew
	err := json.Unmarshal(payload, &cn)
	if err != nil {
		return nil, err
	}
	return &cn, nil
}

// CommentNewReply is the reply to the CommentNew command.
type CommentNewReply struct {
	Comment comments.Comment `json:"comment"`
}

// EncodeCommentNewReply encodes a CommentNewReply into a JSON byte slice.
func EncodeCommentNewReply(cnr CommentNewReply) ([]byte, error) {
	return json.Marshal(cnr)
}

// DecodeCommentNewReply decodes a JSON byte slice into a CommentNewReply.
func DecodeCommentNewReply(payload []byte) (*CommentNewReply, error) {
	var cnr CommentNewReply
	err := json.Unmarshal(payload, &cnr)
	if err != nil {
		return nil, err
	}
	return &cnr, nil
}

// CommentCensor permanently deletes the provided comment. This command relies
// on the comments plugin Del command, but also performs additional vote status
// validation that is specific to pi.
//
// Signature is the client signature of the State+Token+CommentID+Reason
type CommentCensor struct {
	State     PropStateT `json:"state"`     // Record state
	Token     string     `json:"token"`     // Record token
	CommentID uint32     `json:"commentid"` // Comment ID
	Reason    string     `json:"reason"`    // Reason for deletion
	PublicKey string     `json:"publickey"` // Public key used for signature
	Signature string     `json:"signature"` // Client signature
}

// EncodeCommentCensor encodes a CommentCensor into a JSON byte slice.
func EncodeCommentCensor(cc CommentCensor) ([]byte, error) {
	return json.Marshal(cc)
}

// DecodeCommentCensor decodes a JSON byte slice into a CommentCensor.
func DecodeCommentCensor(payload []byte) (*CommentCensor, error) {
	var cc CommentCensor
	err := json.Unmarshal(payload, &cc)
	if err != nil {
		return nil, err
	}
	return &cc, nil
}

// CommentCensorReply is the reply to the CommentCensor command.
type CommentCensorReply struct {
	Comment comments.Comment `json:"comment"`
}

// EncodeCommentCensorReply encodes a CommentCensorReply into a JSON byte
// slice.
func EncodeCommentCensorReply(ccr CommentCensorReply) ([]byte, error) {
	return json.Marshal(ccr)
}

// DecodeCommentCensorReply decodes a JSON byte slice into CommentCensorReply.
func DecodeCommentCensorReply(payload []byte) (*CommentCensorReply, error) {
	var d CommentCensorReply
	err := json.Unmarshal(payload, &d)
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// CommentVote casts a comment vote (upvote or downvote). This command relies
// on the comments plugin Del command, but also performs additional vote status
// validation that is specific to pi.
//
// The effect of a new vote on a comment score depends on the previous vote
// from that user ID. Example, a user upvotes a comment that they have already
// upvoted, the resulting vote score is 0 due to the second upvote removing the
// original upvote. The public key cannot be relied on to remain the same for
// each user so a user ID must be included.
//
// Signature is the client signature of the State+Token+CommentID+Vote.
type CommentVote struct {
	UserID    string       `json:"userid"`    // Unique user ID
	State     PropStateT   `json:"state"`     // Record state
	Token     string       `json:"token"`     // Record token
	CommentID uint32       `json:"commentid"` // Comment ID
	Vote      CommentVoteT `json:"vote"`      // Upvote or downvote
	PublicKey string       `json:"publickey"` // Public key used for signature
	Signature string       `json:"signature"` // Client signature
}

// EncodeCommentVote encodes a CommentVote into a JSON byte slice.
func EncodeCommentVote(cv CommentVote) ([]byte, error) {
	return json.Marshal(cv)
}

// DecodeCommentVote decodes a JSON byte slice into a CommentVote.
func DecodeCommentVote(payload []byte) (*CommentVote, error) {
	var cv CommentVote
	err := json.Unmarshal(payload, &cv)
	if err != nil {
		return nil, err
	}
	return &cv, nil
}

// CommentVoteReply is the reply to the CommentVote command.
type CommentVoteReply struct {
	Downvotes uint64 `json:"downvotes"` // Tolal downvotes on comment
	Upvotes   uint64 `json:"upvotes"`   // Total upvotes on comment
	Timestamp int64  `json:"timestamp"` // Received UNIX timestamp
	Receipt   string `json:"receipt"`   // Server signature of client signature
}

// EncodeCommentVoteReply encodes a CommentVoteReply into a JSON byte slice.
func EncodeCommentVoteReply(cvr CommentVoteReply) ([]byte, error) {
	return json.Marshal(cvr)
}

// DecodeCommentVoteReply decodes a JSON byte slice into a CommentVoteReply.
func DecodeCommentVoteReply(payload []byte) (*CommentVoteReply, error) {
	var cvr CommentVoteReply
	err := json.Unmarshal(payload, &cvr)
	if err != nil {
		return nil, err
	}
	return &cvr, nil
}

// ProposalInv retrieves the tokens of all proposals in the inventory that
// match the provided filtering criteria. The returned proposals are
// categorized by proposal state and status. If no filtering criteria is
// provided then the full proposal inventory is returned.
type ProposalInv struct {
	UserID string `json:"userid,omitempty"`
}

// EncodeProposalInv encodes a ProposalInv into a JSON byte slice.
func EncodeProposalInv(pi ProposalInv) ([]byte, error) {
	return json.Marshal(pi)
}

// DecodeProposalInv decodes a JSON byte slice into a ProposalInv.
func DecodeProposalInv(payload []byte) (*ProposalInv, error) {
	var pi ProposalInv
	err := json.Unmarshal(payload, &pi)
	if err != nil {
		return nil, err
	}
	return &pi, nil
}

// ProposalInvReply is the reply to the ProposalInv command. The returned maps
// contains map[status][]token where the status is the human readable proposal
// status and the token is the proposal token.
type ProposalInvReply struct {
	Unvetted map[string][]string `json:"unvetted"`
	Vetted   map[string][]string `json:"vetted"`
}

// EncodeProposalInvReply encodes a ProposalInvReply into a JSON
// byte slice.
func EncodeProposalInvReply(pir ProposalInvReply) ([]byte, error) {
	return json.Marshal(pir)
}

// DecodeProposalInvReply decodes a JSON byte slice into a
// ProposalInvReply.
func DecodeProposalInvReply(payload []byte) (*ProposalInvReply, error) {
	var pir ProposalInvReply
	err := json.Unmarshal(payload, &pir)
	if err != nil {
		return nil, err
	}
	return &pir, nil
}

// VoteInventory requests the tokens of all proposals in the inventory
// categorized by their vote status. This call relies on the ticketvote
// Inventory call, but breaks the Finished vote status out into Approved and
// Rejected categories. This functionality is specific to pi.
type VoteInventory struct{}

// EncodeVoteInventory encodes a VoteInventory into a JSON byte slice.
func EncodeVoteInventory(vi VoteInventory) ([]byte, error) {
	return json.Marshal(vi)
}

// DecodeVoteInventory decodes a JSON byte slice into a VoteInventory.
func DecodeVoteInventory(payload []byte) (*VoteInventory, error) {
	var vi VoteInventory
	err := json.Unmarshal(payload, &vi)
	if err != nil {
		return nil, err
	}
	return &vi, nil
}

// VoteInventoryReply is the reply to the VoteInventory command.
type VoteInventoryReply struct {
	Unauthorized []string `json:"unauthorized"`
	Authorized   []string `json:"authorized"`
	Started      []string `json:"started"`
	Approved     []string `json:"approved"`
	Rejected     []string `json:"rejected"`

	// BestBlock is the best block value that was used to prepare the
	// inventory.
	BestBlock uint32 `json:"bestblock"`
}

// EncodeVoteInventoryReply encodes a VoteInventoryReply into a JSON byte
// slice.
func EncodeVoteInventoryReply(vir VoteInventoryReply) ([]byte, error) {
	return json.Marshal(vir)
}

// DecodeVoteInventoryReply decodes a JSON byte slice into VoteInventoryReply.
func DecodeVoteInventoryReply(payload []byte) (*VoteInventoryReply, error) {
	var vir VoteInventoryReply
	err := json.Unmarshal(payload, &vir)
	if err != nil {
		return nil, err
	}
	return &vir, nil
}
