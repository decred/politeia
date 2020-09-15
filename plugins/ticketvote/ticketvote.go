// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package ticketvote provides a plugin for creating and managing votes that
// require decred tickets to participate.
package ticketvote

import (
	"encoding/json"
	"fmt"
)

type ActionT string
type VoteT int
type VoteStatusT int
type VoteErrorT int
type ErrorStatusT int

const (
	ID = "ticketvote"

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
	// TODO these are not used anywhere
	VoteDurationMinMainnet = 2016
	VoteDurationMaxMainnet = 4032
	VoteDurationMinTestnet = 0
	VoteDurationMaxTestnet = 4032

	// Vote option IDs
	VoteOptionIDApprove = "yes"
	VoteOptionIDReject  = "no"

	// Vote error status codes. Vote errors are errors that occur while
	// attempting to cast a vote. These errors are returned with the
	// individual failed vote.
	// TODO change politeiavoter to use these error codes
	VoteErrorInvalid             VoteErrorT = 0
	VoteErrorInternalError       VoteErrorT = 1
	VoteErrorTokenInvalid        VoteErrorT = 2
	VoteErrorRecordNotFound      VoteErrorT = 3
	VoteErrorMultipleRecordVotes VoteErrorT = 4
	VoteErrorVoteStatusInvalid   VoteErrorT = 5
	VoteErrorVoteBitInvalid      VoteErrorT = 6
	VoteErrorSignatureInvalid    VoteErrorT = 7
	VoteErrorTicketNotEligible   VoteErrorT = 8
	VoteErrorTicketAlreadyVoted  VoteErrorT = 9

	// User error status codes
	ErrorStatusInvalid              ErrorStatusT = 0
	ErrorStatusTokenInvalid         ErrorStatusT = 1
	ErrorStatusPublicKeyInvalid     ErrorStatusT = 2
	ErrorStatusSignatureInvalid     ErrorStatusT = 3
	ErrorStatusRecordNotFound       ErrorStatusT = 4
	ErrorStatusRecordStatusInvalid  ErrorStatusT = 5
	ErrorStatusAuthorizationInvalid ErrorStatusT = 6
	ErrorStatusVoteDetailsInvalid   ErrorStatusT = 7
	ErrorStatusVoteStatusInvalid    ErrorStatusT = 8
	ErrorStatusBallotInvalid        ErrorStatusT = 9
)

var (
	VoteStatus = map[VoteStatusT]string{
		VoteStatusInvalid:      "vote status invalid",
		VoteStatusUnauthorized: "unauthorized",
		VoteStatusAuthorized:   "authorized",
		VoteStatusStarted:      "started",
		VoteStatusFinished:     "finished",
	}

	VoteError = map[VoteErrorT]string{
		VoteErrorInvalid:             "vote error invalid",
		VoteErrorInternalError:       "internal server error",
		VoteErrorTokenInvalid:        "token invalid",
		VoteErrorRecordNotFound:      "record not found",
		VoteErrorMultipleRecordVotes: "attempting to vote on multiple records",
		VoteErrorVoteStatusInvalid:   "record vote status invalid",
		VoteErrorVoteBitInvalid:      "vote bit invalid",
		VoteErrorSignatureInvalid:    "signature invalid",
		VoteErrorTicketNotEligible:   "ticket not eligible",
		VoteErrorTicketAlreadyVoted:  "ticket already voted",
	}

	// ErrorStatus contains human readable user error statuses.
	ErrorStatus = map[ErrorStatusT]string{
		ErrorStatusInvalid:              "error status invalid",
		ErrorStatusTokenInvalid:         "token invalid",
		ErrorStatusPublicKeyInvalid:     "public key invalid",
		ErrorStatusSignatureInvalid:     "signature invalid",
		ErrorStatusRecordNotFound:       "record not found",
		ErrorStatusRecordStatusInvalid:  "record status invalid",
		ErrorStatusAuthorizationInvalid: "authorization invalid",
		ErrorStatusVoteDetailsInvalid:   "vote details invalid",
		ErrorStatusVoteStatusInvalid:    "vote status invalid",
		ErrorStatusBallotInvalid:        "ballot invalid",
	}
)

// UserErrorReply represents an error that is caused by the user.
type UserErrorReply struct {
	ErrorCode    ErrorStatusT
	ErrorContext []string
}

// Error satisfies the error interface.
func (e UserErrorReply) Error() string {
	return fmt.Sprintf("ticketvote plugin error code: %v", e.ErrorCode)
}

// AuthorizeVote is the structure that is saved to disk when a vote is
// authorized or a previous authorization is revoked.
type AuthorizeVote struct {
	// Data generated by client
	Token     string `json:"token"`     // Record token
	Version   uint32 `json:"version"`   // Record version
	Action    string `json:"action"`    // Authorize or revoke
	PublicKey string `json:"publickey"` // Public key used for signature
	Signature string `json:"signature"` // Signature of token+version+action

	// Metadata generated by server
	Timestamp int64  `json:"timestamp"` // Received UNIX timestamp
	Receipt   string `json:"receipt"`   // Server signature of client signature
}

// StartVote is the structure that is saved to disk when a vote is started.
// TODO does this need a receipt?
type StartVote struct {
	// Data generated by client
	Vote      VoteDetails `json:"vote"`
	PublicKey string      `json:"publickey"`

	// Signature is the client signature of the SHA256 digest of the
	// JSON encoded Vote struct.
	Signature string `json:"signature"`

	// Metadata generated by server
	StartBlockHeight uint32   `json:"startblockheight"`
	StartBlockHash   string   `json:"startblockhash"`
	EndBlockHeight   uint32   `json:"endblockheight"`
	EligibleTickets  []string `json:"eligibletickets"` // Ticket hashes
}

// CastVote is the structure that is saved to disk when a vote is cast.
// TODO VoteOption.Bit is a uint64, but the CastVote.VoteBit is a string in
// decredplugin. Do we want to make them consistent or was that done on
// purpose? It was probably done that way so that way for the signature.
type CastVote struct {
	// Data generated by client
	Token     string `json:"token"`     // Record token
	Ticket    string `json:"ticket"`    // Ticket hash
	VoteBit   string `json:"votebits"`  // Selected vote bit, hex encoded
	Signature string `json:"signature"` // Signature of Token+Ticket+VoteBit

	// Metdata generated by server
	Receipt string `json:"receipt"` // Server signature of client signature
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

// EncodeAuthorizeReply encodes an AuthorizeReply into a JSON byte slice.
func EncodeAuthorizeReply(ar AuthorizeReply) ([]byte, error) {
	return json.Marshal(ar)
}

// DecodeAuthorizeReply decodes a JSON byte slice into a AuthorizeReply.
func DecodeAuthorizeReply(payload []byte) (*AuthorizeReply, error) {
	var ar AuthorizeReply
	err := json.Unmarshal(payload, &ar)
	if err != nil {
		return nil, err
	}
	return &ar, nil
}

// VoteOption describes a single vote option.
type VoteOption struct {
	ID          string `json:"id"`          // Single, unique word (e.g. yes)
	Description string `json:"description"` // Longer description of the vote
	Bit         uint64 `json:"bit"`         // Bit used for this option
}

// VoteDetails describes the options and parameters of a ticket vote.
type VoteDetails struct {
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
	Vote      VoteDetails `json:"vote"`      // Vote options and params
	PublicKey string      `json:"publickey"` // Public key used for signature

	// Signature is the signature of a SHA256 digest of the JSON
	// encoded Vote structure.
	Signature string `json:"signature"`
}

// EncodeStart encodes a Start into a JSON byte slice.
func EncodeStart(s Start) ([]byte, error) {
	return json.Marshal(s)
}

// DecodeStart decodes a JSON byte slice into a Start.
func DecodeStart(payload []byte) (*Start, error) {
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
	EligibleTickets  []string `json:"eligibletickets"` // Ticket hashes
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

// Vote is a signed ticket vote. This structure gets saved to disk when
// a vote is cast.
type Vote struct {
	Token     string `json:"token"`     // Record token
	Ticket    string `json:"ticket"`    // Ticket ID
	VoteBit   string `json:"votebits"`  // Selected vote bit, hex encoded
	Signature string `json:"signature"` // Signature of Token+Ticket+VoteBit
}

// VoteReply contains the receipt for the cast vote.
type VoteReply struct {
	Ticket  string `json:"ticket"`  // Ticket ID
	Receipt string `json:"receipt"` // Server signature of client signature

	// The follwing fields will only be present if an error occured
	// while attempting to cast the vote.
	ErrorCode    VoteErrorT `json:"errorcode,omitempty"`
	ErrorContext string     `json:"errorcontext,omitempty"`
}

// Ballot is a batch of votes that are sent to the server. A ballot can only
// contain the votes for a single record.
type Ballot struct {
	Votes []Vote `json:"votes"`
}

// EncodeBallot encodes a Ballot into a JSON byte slice.
func EncodeBallot(b Ballot) ([]byte, error) {
	return json.Marshal(b)
}

// DecodeBallot decodes a JSON byte slice into a Ballot.
func DecodeBallot(payload []byte) (*Ballot, error) {
	var b Ballot
	err := json.Unmarshal(payload, &b)
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// BallotReply is a reply to a batched list of votes.
type BallotReply struct {
	Receipts []VoteReply `json:"receipts"`
}

// EncodeBallot encodes a Ballot into a JSON byte slice.
func EncodeBallotReply(b BallotReply) ([]byte, error) {
	return json.Marshal(b)
}

// DecodeBallotReply decodes a JSON byte slice into a BallotReply.
func DecodeBallotReply(payload []byte) (*BallotReply, error) {
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
func DecodeDetails(payload []byte) (*Details, error) {
	var d Details
	err := json.Unmarshal(payload, &d)
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// DetailsReply is the reply to the Details command.
type DetailsReply struct {
	Auths []AuthorizeVote `json:"auths"`
	Vote  *StartVote      `json:"vote"`
}

// EncodeDetailsReply encodes a DetailsReply into a JSON byte slice.
func EncodeDetailsReply(dr DetailsReply) ([]byte, error) {
	return json.Marshal(dr)
}

// DecodeDetailsReply decodes a JSON byte slice into a DetailsReply.
func DecodeDetailsReply(payload []byte) (*DetailsReply, error) {
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
func DecodeCastVotes(payload []byte) (*CastVotes, error) {
	var cv CastVotes
	err := json.Unmarshal(payload, &cv)
	if err != nil {
		return nil, err
	}
	return &cv, nil
}

// CastVotesReply is the rely to the CastVotes command.
type CastVotesReply struct {
	Votes []CastVote `json:"votes"`
}

// EncodeCastVotesReply encodes a CastVotesReply into a JSON byte slice.
func EncodeCastVotesReply(cvr CastVotesReply) ([]byte, error) {
	return json.Marshal(cvr)
}

// DecodeCastVotesReply decodes a JSON byte slice into a CastVotesReply.
func DecodeCastVotesReply(payload []byte) (*CastVotesReply, error) {
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
func DecodeSummaries(payload []byte) (*Summaries, error) {
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
	VoteBit     uint64 `json:"votebit"`     // Bits used for this option
	Votes       uint64 `json:"votes"`       // Votes cast for this option
}

// Summary summarizes the vote params and results for a ticket vote.
type Summary struct {
	Type             VoteT       `json:"type"`
	Status           VoteStatusT `json:"status"`
	Duration         uint32      `json:"duration"`
	StartBlockHeight uint32      `json:"startblockheight"`
	StartBlockHash   string      `json:"startblockhash"`
	EndBlockHeight   uint32      `json:"endblockheight"`
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
	// summaries.
	BestBlock uint32 `json:"bestblock"`
}

// EncodeSummariesReply encodes a SummariesReply into a JSON byte slice.
func EncodeSummariesReply(sr SummariesReply) ([]byte, error) {
	return json.Marshal(sr)
}

// DecodeSummariesReply decodes a JSON byte slice into a SummariesReply.
func DecodeSummariesReply(payload []byte) (*SummariesReply, error) {
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
func DecodeInventory(payload []byte) (*Inventory, error) {
	var i Inventory
	err := json.Unmarshal(payload, &i)
	if err != nil {
		return nil, err
	}
	return &i, nil
}

// InventoryReply is the reply to the Inventory command. It contains the tokens
// of all public, non-abandoned records catagorized by vote status.
// TODO
// Sorted by timestamp in descending order:
// Unauthorized, Authorized
//
// Sorted by voting period end block height in descending order:
// Started, Finished
//
// TODO the pi plugin will need to catagorize finished into approved and
// rejected.
type InventoryReply struct {
	Unauthorized []string `json:"unauthorized"`
	Authorized   []string `json:"authorized"`
	Started      []string `json:"started"`
	Finished     []string `json:"finished"`

	// BestBlock is the best block value that was used to prepare the
	// inventory.
	BestBlock uint32 `json:"bestblock"`
}

// EncodeInventoryReply encodes a InventoryReply into a JSON byte slice.
func EncodeInventoryReply(ir InventoryReply) ([]byte, error) {
	return json.Marshal(ir)
}

// DecodeInventoryReply decodes a JSON byte slice into a InventoryReply.
func DecodeInventoryReply(payload []byte) (*InventoryReply, error) {
	var ir InventoryReply
	err := json.Unmarshal(payload, &ir)
	if err != nil {
		return nil, err
	}
	return &ir, nil
}