// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package ticketvote provides a plugin for running votes that require decred
// tickets to participate.
package ticketvote

import (
	"encoding/json"
)

type VoteStatusT int
type AuthActionT string
type VoteT int
type VoteErrorT int
type ErrorStatusT int

// TODO VoteDetails, StartReply, StartRunoffReply should contain a receipt.
// The receipt should be the server signature of Signature+StartBlockHash.

const (
	ID      = "ticketvote"
	Version = "1"

	// Plugin commands
	CmdAuthorize   = "authorize"   // Authorize a vote
	CmdStart       = "start"       // Start a vote
	CmdStartRunoff = "startrunoff" // Start a runoff vote
	CmdBallot      = "ballot"      // Cast a ballot of votes
	CmdDetails     = "details"     // Get vote details
	CmdCastVotes   = "castvotes"   // Get cast votes
	CmdSummaries   = "summaries"   // Get vote summaries
	CmdInventory   = "inventory"   // Get inventory grouped by vote status
	CmdProofs      = "proofs"      // Get inclusion proofs

	// Default plugin settings
	DefaultMainNetVoteDurationMin = 2016
	DefaultMainNetVoteDurationMax = 4032
	DefaultTestNetVoteDurationMin = 0
	DefaultTestNetVoteDurationMax = 4032
	DefaultSimNetVoteDurationMin  = 0
	DefaultSimNetVoteDurationMax  = 4032

	// TODO implement PolicyVotesPageSize
	// PolicyVotesPageSize is the maximum number of results that can be
	// returned from any of the batched vote commands.
	PolicyVotesPageSize = 20

	// Vote statuses
	VoteStatusInvalid      VoteStatusT = 0 // Invalid status
	VoteStatusUnauthorized VoteStatusT = 1 // Vote cannot be started
	VoteStatusAuthorized   VoteStatusT = 2 // Vote can be started
	VoteStatusStarted      VoteStatusT = 3 // Vote has been started
	VoteStatusFinished     VoteStatusT = 4 // Vote has finished

	// Authorize vote actions
	ActionAuthorize AuthActionT = "authorize"
	ActionRevoke    AuthActionT = "revoke"

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
	// it's possible for a record to meet both the quorum and pass
	// requirements but still be rejected if it does not have the most
	// net yes votes.
	VoteTypeRunoff VoteT = 2

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
	ErrorStatusVoteParamsInvalid    ErrorStatusT = 7
	ErrorStatusVoteStatusInvalid    ErrorStatusT = 8
	ErrorStatusBallotInvalid        ErrorStatusT = 9
	ErrorStatusPageSizeExceeded     ErrorStatusT = 10
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
		ErrorStatusVoteParamsInvalid:    "vote params invalid",
		ErrorStatusVoteStatusInvalid:    "vote status invalid",
		ErrorStatusBallotInvalid:        "ballot invalid",
		ErrorStatusPageSizeExceeded:     "page size exceeded",
	}
)

// AuthorizeDetails is the structure that is saved to disk when a vote is
// authorized or a previous authorization is revoked. It contains all the
// fields from a Authorize and a AuthorizeReply.
type AuthorizeDetails struct {
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

// VoteOption describes a single vote option.
type VoteOption struct {
	ID          string `json:"id"`          // Single, unique word (e.g. yes)
	Description string `json:"description"` // Longer description of the vote
	Bit         uint64 `json:"bit"`         // Bit used for this option
}

// VoteParams describes the options and parameters of a ticket vote.
type VoteParams struct {
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

// VoteDetails is the structure that is saved to disk when a vote is started.
// It contains all of the fields from a Start and a StartReply.
//
// Signature is the client signature of the SHA256 digest of the JSON encoded
// Vote struct.
//
// TODO does this need a receipt?
type VoteDetails struct {
	// Data generated by client
	Params    VoteParams `json:"params"`
	PublicKey string     `json:"publickey"`
	Signature string     `json:"signature"`

	// Metadata generated by server
	StartBlockHeight uint32   `json:"startblockheight"`
	StartBlockHash   string   `json:"startblockhash"`
	EndBlockHeight   uint32   `json:"endblockheight"`
	EligibleTickets  []string `json:"eligibletickets"` // Ticket hashes
}

// CastVoteDetails is the structure that is saved to disk when a vote is cast.
//
// TODO VoteOption.Bit is a uint64, but the CastVote.VoteBit is a string in
// decredplugin. Do we want to make them consistent or was that done on
// purpose? It was probably done that way so that way for the signature.
type CastVoteDetails struct {
	// Data generated by client
	Token     string `json:"token"`     // Record token
	Ticket    string `json:"ticket"`    // Ticket hash
	VoteBit   string `json:"votebits"`  // Selected vote bit, hex encoded
	Signature string `json:"signature"` // Signature of Token+Ticket+VoteBit

	// Metdata generated by server
	Receipt string `json:"receipt"` // Server signature of client signature
}

// Authorize authorizes a ticket vote or revokes a previous authorization.
//
// Signature contains the client signature of the Token+Version+Action.
type Authorize struct {
	Token     string      `json:"token"`     // Record token
	Version   uint32      `json:"version"`   // Record version
	Action    AuthActionT `json:"action"`    // Authorize or revoke
	PublicKey string      `json:"publickey"` // Public key used for signature
	Signature string      `json:"signature"` // Client signature
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

// Start starts a ticket vote.
//
// Signature is the signature of a SHA256 digest of the JSON encoded Vote
// structure.
type Start struct {
	Params    VoteParams `json:"params"`
	PublicKey string     `json:"publickey"` // Public key used for signature
	Signature string     `json:"signature"` // Client signature
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
//
// TODO should this return a receipt?
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
func DecodeStartReply(payload []byte) (*StartReply, error) {
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
	Token  string      `json:"token"` // RFP token
	Auths  []Authorize `json:"auths"`
	Starts []Start     `json:"starts"`
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
//
// TODO should this return a receipt?
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

// CastVote is a signed ticket vote. This structure gets saved to disk when
// a vote is cast.
type CastVote struct {
	Token     string `json:"token"`     // Record token
	Ticket    string `json:"ticket"`    // Ticket ID
	VoteBit   string `json:"votebits"`  // Selected vote bit, hex encoded
	Signature string `json:"signature"` // Signature of Token+Ticket+VoteBit
}

// CastVoteReply contains the receipt for the cast vote.
type CastVoteReply struct {
	Ticket  string `json:"ticket"`  // Ticket ID
	Receipt string `json:"receipt"` // Server signature of client signature

	// The follwing fields will only be present if an error occurred
	// while attempting to cast the vote.
	ErrorCode    VoteErrorT `json:"errorcode,omitempty"`
	ErrorContext string     `json:"errorcontext,omitempty"`
}

// Ballot is a batch of votes that are sent to the server. A ballot can only
// contain the votes for a single record.
type Ballot struct {
	Votes []CastVote `json:"votes"`
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
	Receipts []CastVoteReply `json:"receipts"`
}

// EncodeBallotReply encodes a Ballot into a JSON byte slice.
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

// Details returns the vote details for each of the provided record tokens.
type Details struct {
	Tokens []string `json:"tokens"`
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

// RecordVote contains all vote authorizations and the vote details for a
// record. The VoteDetails will be nil if the vote has been started.
type RecordVote struct {
	Auths []AuthorizeDetails `json:"auths"`
	Vote  *VoteDetails       `json:"vote"`
}

// DetailsReply is the reply to the Details command. The returned map will not
// contain an entry for any tokens that did not correspond to an actual record.
// It is the callers responsibility to ensure that a entry is returned for all
// of the provided tokens.
type DetailsReply struct {
	Votes map[string]RecordVote `json:"votes"`
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
	Votes []CastVoteDetails `json:"votes"`
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
// categorized by vote status.
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
// of all public, non-abandoned records categorized by vote status.
// TODO
// Sorted by timestamp in descending order:
// Unauthorized, Authorized
//
// Sorted by voting period end block height in descending order:
// Started, Finished
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
