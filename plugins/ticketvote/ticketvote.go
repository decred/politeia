// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"encoding/json"
	"fmt"
)

type ActionT string
type VoteT int
type VoteStatusT int
type ErrorStatusT int

const (
	Version uint32 = 1
	ID             = "ticketvotes"

	// Plugin commands
	CmdAuthorize   = "authorize"   // Authorize a vote
	CmdStart       = "start"       // Start a vote
	CmdStartRunoff = "startrunoff" // Start a runoff vote
	CmdBallot      = "ballot"      // Cast a ballot of votes
	CmdDetails     = "details"     // Get details of a vote
	CmdCastVotes   = "castvotes"   // Get cast votes
	CmdSummaries   = "summaries"   // Get vote summaries
	CmdInventory   = "inventory"   // Get inventory grouped by vote status
	CmdProofs      = "proofs"      // Get inclusion proofs

	// Authorize vote actions
	ActionAuthorize ActionT = "authorize"
	ActionRevoke    ActionT = "revoke"

	// Vote statuses
	VoteStatusInvalid      VoteStatusT = 0 // Invalid status
	VoteStatusUnauthorized VoteStatusT = 1 // Vote cannot be started
	VoteStatusAuthorized   VoteStatusT = 2 // Vote can be started
	VoteStatusStarted      VoteStatusT = 3 // Vote has been started
	VoteStatusFinished     VoteStatusT = 4 // Vote has finished

	// Vote types
	VoteTypeInvalid VoteT = 0

	// VoteTypeStandard is used to indicate a simple approve or reject
	// vote where the winner is the voting option that has met the
	// specified quorum and pass requirements.
	VoteTypeStandard VoteT = 1

	// VoteTypeRunoff specifies a runoff vote that multiple records
	// compete in. All records are voted on like normal, but there can
	// only be one winner in a runoff vote. The winner is the record
	// that meets the quorum requirement, meets the pass requirement,
	// and that has the most net yes votes. The winning record is
	// considered approved and all other records are considered to be
	// rejected. If no records meet the quorum and pass requirements
	// then all records are considered rejected. Note, in a runoff vote
	// it's possible for a proposal to meet both the quorum and pass
	// requirements but still be rejected if it does not have the most
	// net yes votes.
	VoteTypeRunoff VoteT = 2

	// Vote duration requirements in blocks
	VoteDurationMinMainnet = 2016
	VoteDurationMaxMainnet = 4032
	VoteDurationMinTestnet = 0
	VoteDurationMaxTestnet = 4032

	// Vote option IDs
	VoteOptionIDApprove = "yes"
	VoteOptionIDReject  = "no"

	// Error status codes
	// TODO change politeiavoter to use these error codes
	ErrorStatusInvalid ErrorStatusT = 0
)

var (
	// ErrorStatus contains human readable error statuses.
	ErrorStatus = map[ErrorStatusT]string{
		ErrorStatusInvalid: "invalid error status",
	}
)

// UserError represents an error that is cause by something that the user did.
type UserError struct {
	ErrorCode    ErrorStatusT
	ErrorContext []string
}

// Error satisfies the error interface.
func (e UserError) Error() string {
	return fmt.Sprintf("plugin error code: %v", e.ErrorCode)
}

// Authorize authorizes a ticket vote or revokes a previous authorization.
type Authorize struct {
	Token     string  `json:"token"`     // Record token
	Version   uint32  `json:"version"`   // Record version
	Action    ActionT `json:"action"`    // Authorize or revoke
	PublicKey string  `json:"publickey"` // Public key used for signature
	Signature string  `json:"signature"` // Signature of token+version+action
}

// EncodeAuthorize encodes an Authorize into a JSON byte slice.
func EncodeAuthorize(a Authorize) ([]byte, error) {
	return json.Marshal(a)
}

// DecodeAuthorize decodes a JSON byte slice into a Authorize.
func DecodeAuthorize(payload []byte) (*Authorize, error) {
	var a Authorize
	err := json.Unmarshal(payload, &a)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// AuthorizeReply is the reply to the Authorize command.
type AuthorizeReply struct {
	Timestamp int64  `json:"timestamp"` // Received UNIX timestamp
	Receipt   string `json:"receipt"`   // Server signature of client signature
}

// VoteOption describes a single vote option.
type VoteOption struct {
	ID          string `json:"id"`          // Single, unique word (e.g. yes)
	Description string `json:"description"` // Longer description of the vote
	Bits        uint64 `json:"bits"`        // Bits used for this option
}

// Vote describes the options and parameters of a ticket vote.
type Vote struct {
	Token    string `json:"token"`    // Record token
	Version  uint32 `json:"version"`  // Record version
	Type     VoteT  `json:"type"`     // Vote type
	Mask     uint64 `json:"mask"`     // Valid vote bits
	Duration uint32 `json:"duration"` // Duration in blocks

	// QuorumPercentage is the percent of elligible votes required for
	// the vote to meet a quorum.
	QuorumPercentage uint32 `json:"quorumpercentage"`

	// PassPercentage is the percent of total votes that are required
	// to consider a vote option as passed.
	PassPercentage uint32 `json:"passpercentage"`

	Options []VoteOption `json:"options"`
}

// Start starts a ticket vote.
type Start struct {
	Vote      Vote   `json:"vote"`      // Vote options and params
	PublicKey string `json:"publickey"` // Public key used for signature

	// Signature is the signature of a SHA256 digest of the JSON
	// encoded Vote structure.
	Signature string `json:"signature"`
}

// EncodeStart encodes a Start into a JSON byte slice.
func EncodeStart(s Start) ([]byte, error) {
	return json.Marshal(s)
}

// DecodeStart decodes a JSON byte slice into a Start.
func DecodeStartVote(payload []byte) (*Start, error) {
	var s Start
	err := json.Unmarshal(payload, &s)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// StartReply is the reply to the Start command.
type StartReply struct {
	StartBlockHeight uint32   `json:"startblockheight"`
	StartBlockHash   string   `json:"startblockhash"`
	EndBlockHeight   uint32   `json:"endblockheight"`
	EligibleTickets  []string `json:"eligibletickets"`
}

// EncodeStartReply encodes a StartReply into a JSON byte slice.
func EncodeStartReply(sr StartReply) ([]byte, error) {
	return json.Marshal(sr)
}

// DecodeStartReply decodes a JSON byte slice into a StartReply.
func DecodeStartReplyVote(payload []byte) (*StartReply, error) {
	var sr StartReply
	err := json.Unmarshal(payload, &sr)
	if err != nil {
		return nil, err
	}
	return &sr, nil
}

// StartRunoff starts a runoff vote between the provided submissions. Each
// submission is required to have its own Authorize and Start.
type StartRunoff struct {
	Token          string      `json:"token"` // RFP token
	Authorizations []Authorize `json:"authorizations"`
	Votes          []Start     `json:"votes"`
}

// EncodeStartRunoff encodes a StartRunoff into a JSON byte slice.
func EncodeStartRunoff(sr StartRunoff) ([]byte, error) {
	return json.Marshal(sr)
}

// DecodeStartRunoff decodes a JSON byte slice into a StartRunoff.
func DecodeStartRunoff(payload []byte) (*StartRunoff, error) {
	var sr StartRunoff
	err := json.Unmarshal(payload, &sr)
	if err != nil {
		return nil, err
	}
	return &sr, nil
}

// StartRunoffReply is the reply to the StartRunoff command.
type StartRunoffReply struct {
	StartBlockHeight uint32   `json:"startblockheight"`
	StartBlockHash   string   `json:"startblockhash"`
	EndBlockHeight   uint32   `json:"endblockheight"`
	EligibleTickets  []string `json:"eligibletickets"`
}

// EncodeStartRunoffReply encodes a StartRunoffReply into a JSON byte slice.
func EncodeStartRunoffReply(srr StartRunoffReply) ([]byte, error) {
	return json.Marshal(srr)
}

// DecodeStartRunoffReply decodes a JSON byte slice into a StartRunoffReply.
func DecodeStartRunoffReply(payload []byte) (*StartRunoffReply, error) {
	var srr StartRunoffReply
	err := json.Unmarshal(payload, &srr)
	if err != nil {
		return nil, err
	}
	return &srr, nil
}

// CastVote is a signed ticket vote.
type CastVote struct {
	Token     string `json:"token"`     // Record token
	Ticket    string `json:"ticket"`    // Ticket ID
	VoteBit   string `json:"votebit"`   // Selected vote bit, hex encoded
	Signature string `json:"signature"` // Signature of Token+Ticket+VoteBit
}

// CatVoteReply contains the receipt for the cast vote. If an error occured
// while casting the vote the receipt will be empty and a error code will be
// present.
type CastVoteReply struct {
	Ticket    string       `json:"ticket"`  // Ticket ID
	Receipt   string       `json:"receipt"` // Server sig of client sig
	ErrorCode ErrorStatusT `json:"errorcode,omitempty"`
}

// Ballot is a batch of votes that are sent to the server.
type Ballot struct {
	Votes []CastVote `json:"votes"`
}

// EncodeBallot encodes a Ballot into a JSON byte slice.
func EncodeBallot(b Ballot) ([]byte, error) {
	return json.Marshal(b)
}

// DecodeBallot decodes a JSON byte slice into a Ballot.
func DecodeBallotVote(payload []byte) (*Ballot, error) {
	var b Ballot
	err := json.Unmarshal(payload, &b)
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// BallotReply is a reply to a batched list of votes.
type BallotReply struct {
	Receipts []CastVoteReply `json:"receipts"`
}

// EncodeBallot encodes a Ballot into a JSON byte slice.
func EncodeBallotReply(b BallotReply) ([]byte, error) {
	return json.Marshal(b)
}

// DecodeBallotReply decodes a JSON byte slice into a BallotReply.
func DecodeBallotReplyVote(payload []byte) (*BallotReply, error) {
	var b BallotReply
	err := json.Unmarshal(payload, &b)
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// Details requests the vote details for the specified record token.
type Details struct {
	Token string `json:"token"`
}

// EncodeDetails encodes a Details into a JSON byte slice.
func EncodeDetails(d Details) ([]byte, error) {
	return json.Marshal(d)
}

// DecodeDetails decodes a JSON byte slice into a Details.
func DecodeDetailsVote(payload []byte) (*Details, error) {
	var d Details
	err := json.Unmarshal(payload, &d)
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// AuthorizeDetails describes the details of a vote authorization.
type AuthorizeDetails struct {
	Token     string `json:"token"`     // Record token
	Version   uint32 `json:"version"`   // Record version
	Action    string `json:"action"`    // Authorize or revoke
	PublicKey string `json:"publickey"` // Public key used for signature
	Signature string `json:"signature"` // Signature of token+version+action
	Timestamp int64  `json:"timestamp"` // Received UNIX timestamp
	Receipt   string `json:"receipt"`   // Server signature of client signature
}

// DetailsReply is the reply to the Details command.
type DetailsReply struct {
	// Auths contains all authorizations and revokes that were made for
	// this ticket vote.
	Auths []AuthorizeDetails `json:"auths"`

	// Vote details
	Vote             Vote     `json:"vote"`             // Vote params
	PublicKey        string   `json:"publickey"`        // Key used for sig
	Signature        string   `json:"signature"`        // Sig of Vote hash
	StartBlockHeight uint32   `json:"startblockheight"` // Start block height
	StartBlockHash   string   `json:"startblockhash"`   // Start block hash
	EndBlockHeight   uint32   `json:"endblockheight"`   // End block height
	EligibleTickets  []string `json:"eligibletickets"`  // Valid voting tickets
}

// EncodeDetailsReply encodes a DetailsReply into a JSON byte slice.
func EncodeDetailsReply(dr DetailsReply) ([]byte, error) {
	return json.Marshal(dr)
}

// DecodeDetailsReply decodes a JSON byte slice into a DetailsReply.
func DecodeDetailsReplyVote(payload []byte) (*DetailsReply, error) {
	var dr DetailsReply
	err := json.Unmarshal(payload, &dr)
	if err != nil {
		return nil, err
	}
	return &dr, nil
}

// CastVotes requests the cast votes for the provided record token.
type CastVotes struct {
	Token string `json:"token"`
}

// EncodeCastVotes encodes a CastVotes into a JSON byte slice.
func EncodeCastVotes(cv CastVotes) ([]byte, error) {
	return json.Marshal(cv)
}

// DecodeCastVotes decodes a JSON byte slice into a CastVotes.
func DecodeCastVotesVote(payload []byte) (*CastVotes, error) {
	var cv CastVotes
	err := json.Unmarshal(payload, &cv)
	if err != nil {
		return nil, err
	}
	return &cv, nil
}

// CastVotesReply is the rely to the CastVotes command.
type CastVotesReply struct {
	CastVotes []CastVote `json:"castvotes"`
}

// EncodeCastVotesReply encodes a CastVotesReply into a JSON byte slice.
func EncodeCastVotesReply(cvr CastVotesReply) ([]byte, error) {
	return json.Marshal(cvr)
}

// DecodeCastVotesReply decodes a JSON byte slice into a CastVotesReply.
func DecodeCastVotesReplyVote(payload []byte) (*CastVotesReply, error) {
	var cvr CastVotesReply
	err := json.Unmarshal(payload, &cvr)
	if err != nil {
		return nil, err
	}
	return &cvr, nil
}

// Summaries requests the vote summaries for the provided record tokens.
type Summaries struct {
	Tokens []string `json:"tokens"`
}

// EncodeSummaries encodes a Summaries into a JSON byte slice.
func EncodeSummaries(s Summaries) ([]byte, error) {
	return json.Marshal(s)
}

// DecodeSummaries decodes a JSON byte slice into a Summaries.
func DecodeSummariesVote(payload []byte) (*Summaries, error) {
	var s Summaries
	err := json.Unmarshal(payload, &s)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// Result describes a vote option and the total number of votes that have been
// cast for this option.
type Result struct {
	ID          string `json:"id"`          // Single unique word (e.g. yes)
	Description string `json:"description"` // Longer description of the vote
	Bits        uint64 `json:"bits"`        // Bits used for this option
	Votes       uint64 `json:"votes"`       // Votes cast for this option
}

// Summary summarizes the vote params and results for a ticket vote.
type Summary struct {
	Type             VoteT       `json:"type"`
	Status           VoteStatusT `json:"status"`
	Duration         uint32      `json:"duration"`
	StartBlockHeight uint32      `json:"startblockheight"`
	EndBlockHeight   string      `json:"endblockheight"`
	EligibleTickets  uint32      `json:"eligibletickets"`
	QuorumPercentage uint32      `json:"quorumpercentage"`
	PassPercentage   uint32      `json:"passpercentage"`
	Results          []Result    `json:"results"`

	// Approved describes whether the vote has been approved. This will
	// only be present when the vote type is VoteTypeStandard or
	// VoteTypeRunoff, both of which only allow for approve/reject
	// voting options.
	Approved bool `json:"approved,omitempty"`
}

// SummariesReply is the reply to the Summaries command.
type SummariesReply struct {
	// Summaries contains a vote summary for each of the provided
	// tokens. The map will not contain an entry for any tokens that
	// did not correspond to an actual record. It is the callers
	// responsibility to ensure that a summary is returned for all of
	// the provided tokens.
	Summaries map[string]Summary `json:"summaries"` // [token]Summary

	// BestBlock is the best block value that was used to prepare the
	// the summaries.
	BestBlock uint64 `json:"bestblock"`
}

// EncodeSummariesReply encodes a SummariesReply into a JSON byte slice.
func EncodeSummariesReply(sr SummariesReply) ([]byte, error) {
	return json.Marshal(sr)
}

// DecodeSummariesReply decodes a JSON byte slice into a SummariesReply.
func DecodeSummariesReplyVote(payload []byte) (*SummariesReply, error) {
	var sr SummariesReply
	err := json.Unmarshal(payload, &sr)
	if err != nil {
		return nil, err
	}
	return &sr, nil
}

// Inventory requests the tokens of all public, non-abandoned records
// catagorized by vote status.
type Inventory struct{}

// EncodeInventory encodes a Inventory into a JSON byte slice.
func EncodeInventory(i Inventory) ([]byte, error) {
	return json.Marshal(i)
}

// DecodeInventory decodes a JSON byte slice into a Inventory.
func DecodeInventoryVote(payload []byte) (*Inventory, error) {
	var i Inventory
	err := json.Unmarshal(payload, &i)
	if err != nil {
		return nil, err
	}
	return &i, nil
}

// InventoryReply is the reply to the Inventory command. It contains the tokens
// of all public, non-abandoned records catagorized by vote status.
type InventoryReply struct {
	Unauthorized []string `json:"unauthorized"`
	Authorized   []string `json:"authorized"`
	Started      []string `json:"started"`
	Finished     []string `json:"finished"`

	// BestBlock is the best block value that was used to prepare
	// the inventory.
	BestBlock uint64 `json:"bestblock"`
}

// EncodeInventoryReply encodes a InventoryReply into a JSON byte slice.
func EncodeInventoryReply(ir InventoryReply) ([]byte, error) {
	return json.Marshal(ir)
}

// DecodeInventoryReply decodes a JSON byte slice into a InventoryReply.
func DecodeInventoryReplyVote(payload []byte) (*InventoryReply, error) {
	var ir InventoryReply
	err := json.Unmarshal(payload, &ir)
	if err != nil {
		return nil, err
	}
	return &ir, nil
}
