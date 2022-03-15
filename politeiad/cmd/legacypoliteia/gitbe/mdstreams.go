// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package gitbe

const (
	// Metadata stream filenames
	MDStreamProposalGeneral = "00.metadata.txt"
	MDStreamStatusChanges   = "02.metadata.txt"
	MDStreamAuthorizeVote   = "13.metadata.txt"
	MDStreamStartVote       = "14.metadata.txt"
	MDStreamStartVoteReply  = "15.metadata.txt"
)

// ProposalGeneralV2 represents general metadata for a proposal.
//
// Signature is the signature of the proposal merkle root. The merkle root
// contains the ordered files and metadata digests. The file digests are first
// in the ordering.
//
// Differences between v1 and v2:
// * Name has been removed and is now part of proposal metadata.
// * Signature has been updated to include propoposal metadata.
type ProposalGeneralV2 struct {
	Version   uint64 `json:"version"`   // Struct version
	Timestamp int64  `json:"timestamp"` // Last update of proposal
	PublicKey string `json:"publickey"` // Key used for signature
	Signature string `json:"signature"` // Proposal signature
}

type RecordStatusT int

var (
	RecordStatusInvalid           RecordStatusT = 0
	RecordStatusNotFound          RecordStatusT = 1
	RecordStatusNotReviewed       RecordStatusT = 2
	RecordStatusCensored          RecordStatusT = 3
	RecordStatusPublic            RecordStatusT = 4
	RecordStatusUnreviewedChanges RecordStatusT = 5
	RecordStatusArchived          RecordStatusT = 6
)

// RecordStatusChangeV2 represents a politeiad record status change and is used
// to store additional status change metadata that would not otherwise be
// captured by the politeiad status change routes.
//
// V2 adds the Signature field, which was erroneously left out of V1.
//
// Signature of is the signature of Token + NewStatus + StatusChangeMessage.
type RecordStatusChangeV2 struct {
	Version             uint          `json:"version"` // Version of this struct
	NewStatus           RecordStatusT `json:"newstatus"`
	StatusChangeMessage string        `json:"statuschangemessage,omitempty"`
	Signature           string        `json:"signature"`
	AdminPubKey         string        `json:"adminpubkey"`
	Timestamp           int64         `json:"timestamp"`
}

// AuthorizeVote is an MDStream that is used to indicate that a proposal has
// been finalized and is ready to be voted on.  The signature and public
// key are from the proposal author.  The author can revoke a previously sent
// vote authorization by setting the Action field to revoke.
type AuthorizeVote struct {
	// Generated by decredplugin
	Version   uint   `json:"version"`   // Version of this structure
	Receipt   string `json:"receipt"`   // Server signature of client signature
	Timestamp int64  `json:"timestamp"` // Received UNIX timestamp

	// Generated by client
	Action    string `json:"action"`    // Authorize or revoke
	Token     string `json:"token"`     // Proposal censorship token
	Signature string `json:"signature"` // Signature of token+version+action
	PublicKey string `json:"publickey"` // Pubkey used for signature
}

// StartVoteV1 was formerly used to start a proposal vote, but is not longer
// accepted. A StartVoteV2 must be used to start a proposal vote.
type StartVoteV1 struct {
	Version   uint   `json:"version"`   // Version of this structure
	PublicKey string `json:"publickey"` // Key used for signature
	Vote      VoteV1 `json:"vote"`      // Vote + options
	Signature string `json:"signature"` // Signature of token
}

// VoteV1 represents the vote options and parameters for a StartVoteV1.
type VoteV1 struct {
	Token            string       `json:"token"`
	Mask             uint64       `json:"mask"`
	Duration         uint32       `json:"duration"`
	QuorumPercentage uint32       `json:"quorumpercentage"`
	PassPercentage   uint32       `json:"passpercentage"`
	Options          []VoteOption `json:"options"`
}

// VoteOption describes a single vote option.
type VoteOption struct {
	Id          string `json:"id"`
	Description string `json:"description"`
	Bits        uint64 `json:"bits"`
}

// StartVoteV2 is used to start a proposal vote.
//
// The message being signed is the SHA256 digest of the VoteV2 JSON byte slice.
//
// Differences between StartVoteV1 and StartVoteV2:
// * Signature is the signature of a hash of the Vote struct. It was
//   previously the signature of just the proposal token.
// * Vote is now a VoteV2. See the VoteV2 comment for more details.
type StartVoteV2 struct {
	Version   uint   `json:"version"`   // Version of this structure
	PublicKey string `json:"publickey"` // Key used for signature
	Vote      VoteV2 `json:"vote"`      // Vote options and params
	Signature string `json:"signature"` // Signature of Vote hash
}

// VoteV2 represents the vote options and vote parameters for a StartVoteV2.
//
// Differences between VoteV1 and VoteV2:
// * Added the ProposalVersion field that specifies the version of the proposal
//   that is being voted on. This was added so that the proposal version is
//   explicitly included in the StartVote signature.
// * Added a Type field in order to specify the vote type.
type VoteV2 struct {
	Token            string       `json:"token"`
	ProposalVersion  uint32       `json:"proposalversion"`
	Type             VoteT        `json:"type"`
	Mask             uint64       `json:"mask"`
	Duration         uint32       `json:"duration"`
	QuorumPercentage uint32       `json:"quorumpercentage"`
	PassPercentage   uint32       `json:"passpercentage"`
	Options          []VoteOption `json:"options"`
}

// VoteT represents the different type of votes.
type VoteT int

var (
	VoteTypeInvalid  VoteT = 0
	VoteTypeStandard VoteT = 1
	VoteTypeRunoff   VoteT = 2
)

// StartVoteReply is the reply to StartVote.
type StartVoteReply struct {
	Version          uint     `json:"version"`          // Version of this struct
	StartBlockHeight string   `json:"startblockheight"` // Block height
	StartBlockHash   string   `json:"startblockhash"`   // Block hash
	EndHeight        string   `json:"endheight"`        // Height of vote end
	EligibleTickets  []string `json:"eligibletickets"`  // Valid voting tickets
}
