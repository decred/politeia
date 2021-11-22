// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

import "fmt"

const (
	// APIRoute is prefixed onto all routes defined in this package.
	APIRoute = "/ticketvote/v1"

	// RoutePolicy returns the policy for the ticketvote API.
	RoutePolicy = "/policy"

	// RouteAuthorize authorizes a record vote.
	RouteAuthorize = "/authorize"

	// RouteStart starts a record vote.
	RouteStart = "/start"

	// RouteCastBallot casts ballot of votes.
	RouteCastBallot = "/castballot"

	// RouteDetails returns the vote details for a record vote.
	RouteDetails = "/details"

	// RouteResults returns the vote results for a record vote.
	RouteResults = "/results"

	// RouteSummaries returns the vote summary for a page of record
	// votes.
	RouteSummaries = "/summaries"

	// RouteSubmissions returns the submissions of a runoff vote.
	RouteSubmissions = "/submissions"

	// RouteInventory returns the tokens of public records in the inventory
	// categorized by vote status.
	RouteInventory = "/inventory"

	// RouteTimestamps returns the timestamps for ticket vote data.
	RouteTimestamps = "/timestamps"
)

// ErrorCodeT represents a user error code.
type ErrorCodeT uint32

const (
	// ErrorCodeInvalid is an invalid error code.
	ErrorCodeInvalid ErrorCodeT = 0

	// ErrorCodeInputInvalid is returned when there is an error
	// while prasing a command payload.
	ErrorCodeInputInvalid ErrorCodeT = 1

	// ErrorCodePublicKeyInvalid is returned when a public key used
	// in a signature is not valid.
	ErrorCodePublicKeyInvalid ErrorCodeT = 2

	// ErrorCodeUnauthorized is returned when the user is not authorized.
	ErrorCodeUnauthorized ErrorCodeT = 3

	// ErrorCodeRecordNotFound is returned when a record not found.
	ErrorCodeRecordNotFound ErrorCodeT = 4

	// ErrorCodeRecordLocked is returned when a record is locked.
	ErrorCodeRecordLocked ErrorCodeT = 5

	// ErrorCodeTokenInvalid is returned when a token is invalid.
	ErrorCodeTokenInvalid ErrorCodeT = 6

	// ErrorCodePageSizeExceeded is returned when the request's page size
	// exceeds the maximum page size of the request.
	ErrorCodePageSizeExceeded ErrorCodeT = 7

	// ErrorCodeDuplicatePayload is returned when a user tries to submit a
	// duplicate payload for the ticketvote plugin, where it tries to write
	// data that already exists. Timestamp data relies on the hash of the
	// payload, therefore duplicate payloads are not allowed since they will
	// cause collisions.
	ErrorCodeDuplicatePayload ErrorCodeT = 8

	// ErrorCodeLast is used by unit tests to verify that all error codes have
	// a human readable entry in the ErrorCodes map. This error will never be
	// returned.
	ErrorCodeLast ErrorCodeT = 9
)

var (
	// ErrorCodes contains the human readable errors.
	ErrorCodes = map[ErrorCodeT]string{
		ErrorCodeInvalid:          "error invalid",
		ErrorCodeInputInvalid:     "input invalid",
		ErrorCodePublicKeyInvalid: "public key invalid",
		ErrorCodeUnauthorized:     "unauthorized",
		ErrorCodeRecordNotFound:   "record not found",
		ErrorCodeRecordLocked:     "record locked",
		ErrorCodeTokenInvalid:     "token is invalid",
		ErrorCodePageSizeExceeded: "page size exceeded",
		ErrorCodeDuplicatePayload: "duplicate payload",
	}
)

// UserErrorReply is the reply that the server returns when it encounters an
// error that is caused by something that the user did (malformed input, bad
// timing, etc). The HTTP status code will be 400.
type UserErrorReply struct {
	ErrorCode    ErrorCodeT `json:"errorcode"`
	ErrorContext string     `json:"errorcontext,omitempty"`
}

// Error satisfies the error interface.
func (e UserErrorReply) Error() string {
	return fmt.Sprintf("user error code: %v", e.ErrorCode)
}

// PluginErrorReply is the reply that the server returns when it encounters
// a plugin error.
type PluginErrorReply struct {
	PluginID     string `json:"pluginid"`
	ErrorCode    uint32 `json:"errorcode"`
	ErrorContext string `json:"errorcontext,omitempty"`
}

// Error satisfies the error interface.
func (e PluginErrorReply) Error() string {
	return fmt.Sprintf("plugin %v error code: %v", e.PluginID, e.ErrorCode)
}

// ServerErrorReply is the reply that the server returns when it encounters an
// unrecoverable error while executing a command. The HTTP status code will be
// 500 and the ErrorCode field will contain a UNIX timestamp that the user can
// provide to the server admin to track down the error details in the logs.
type ServerErrorReply struct {
	ErrorCode int64 `json:"errorcode"`
}

// Error satisfies the error interface.
func (e ServerErrorReply) Error() string {
	return fmt.Sprintf("server error: %v", e.ErrorCode)
}

// Policy requests the ticketvote policy.
type Policy struct{}

// PolicyReply is the reply to the Policy command.
type PolicyReply struct {
	LinkByPeriodMin    int64  `json:"linkbyperiodmin"` // In seconds
	LinkByPeriodMax    int64  `json:"linkbyperiodmax"` // In seconds
	VoteDurationMin    uint32 `json:"votedurationmin"` // In blocks
	VoteDurationMax    uint32 `json:"votedurationmax"` // In blocks
	SummariesPageSize  uint32 `json:"summariespagesize"`
	InventoryPageSize  uint32 `json:"inventorypagesize"`
	TimestampsPageSize uint32 `json:"timestampspagesize"`
}

// AuthActionT represents an Authorize action.
type AuthActionT string

const (
	// AuthActionAuthorize is used to authorize a record vote.
	AuthActionAuthorize AuthActionT = "authorize"

	// AuthActionRevoke is used to revoke a previous authorization.
	AuthActionRevoke AuthActionT = "revoke"
)

// Authorize authorizes a record vote or revokes a previous vote
// authorization. Not all vote types require an authorization.
//
// Signature contains the client signature of the Token+Version+Action.
type Authorize struct {
	Token     string      `json:"token"`
	Version   uint32      `json:"version"`
	Action    AuthActionT `json:"action"`
	PublicKey string      `json:"publickey"`
	Signature string      `json:"signature"`
}

// AuthorizeReply is the reply to the Authorize command.
//
// Receipt is the server signature of the client signature. This is proof that
// the server received and processed the Authorize command.
type AuthorizeReply struct {
	Timestamp int64  `json:"timestamp"`
	Receipt   string `json:"receipt"`
}

// VoteT represents a vote type.
type VoteT uint32

const (
	// VoteTypeInvalid represents and invalid vote type.
	VoteTypeInvalid VoteT = 0

	// VoteTypeStandard is used to indicate a simple approve or reject
	// vote where the winner is the voting option that has met the
	// specified quorum and pass requirements. Standard votes require
	// an authorization from the record author before the voting period
	// can be started by an admin.
	VoteTypeStandard VoteT = 1

	// VoteTypeRunoff specifies a runoff vote that multiple records
	// compete in. All records are voted on like normal and all votes
	// are simple approve/reject votes, but there can only be one
	// winner in a runoff vote. The winner is the record that meets
	// the quorum requirement, meets the pass requirement, and that has
	// the most net yes votes. The winning record is considered
	// approved and all other records are considered to be rejected.
	// If no records meet the quorum and pass requirements then all
	// records are considered rejected. Note, in a runoff vote it is
	// possible for a record to meet both the quorum and pass
	// requirements but still be rejected if it does not have the most
	// net yes votes.
	VoteTypeRunoff VoteT = 2

	// VoteTypeLast unit test only.
	VoteTypeLast VoteT = 3
)

var (
	// VoteTypes contains the human readable vote types.
	VoteTypes = map[VoteT]string{
		VoteTypeInvalid:  "invalid vote type",
		VoteTypeStandard: "standard",
		VoteTypeRunoff:   "runoff",
	}
)

const (
	// VoteOptionIDApprove is the vote option ID that indicates the
	// record should be approved. Standard votes and runoff vote
	// submissions are required to use this vote option ID.
	VoteOptionIDApprove = "yes"

	// VoteOptionIDReject is the vote option ID that indicates the
	// record should be rejected. Standard votes and runoff vote
	// submissions are required to use this vote option ID.
	VoteOptionIDReject = "no"
)

// VoteStatusT represents a vote status.
type VoteStatusT uint32

const (
	// VoteStatusInvalid represents an invalid vote status.
	VoteStatusInvalid VoteStatusT = 0

	// VoteStatusUnauthorized represents a vote that has not been
	// authorized yet. Some vote types require prior authorization from
	// the record author before an admin can start the voting period.
	VoteStatusUnauthorized VoteStatusT = 1

	// VoteStatusAuthorized represents a vote that has been authorized.
	// Some vote types require prior authorization from the record
	// author before an admin can start the voting period.
	VoteStatusAuthorized VoteStatusT = 2

	// VoteStatusStarted represents a vote that has been started and
	// is still ongoing.
	VoteStatusStarted VoteStatusT = 3

	// VoteStatusFinished indicates the ticket vote has finished. This
	// vote status is used for vote types that do not have a clear
	// approved or rejected outcome, such as multiple choice votes.
	VoteStatusFinished VoteStatusT = 4

	// VoteStatusApproved indicates that a vote has finished and the
	// vote has met the criteria for being approved. This vote status
	// is only used when the vote type allows for a clear approved or
	// rejected outcome.
	VoteStatusApproved VoteStatusT = 5

	// VoteStatusRejected indicates that a vote has finished and the
	// vote did NOT the criteria for being approved. This vote status
	// is only used when the vote type allows for a clear approved or
	// rejected outcome.
	VoteStatusRejected VoteStatusT = 6

	// VoteStatusIneligible indicates that a record is not eligible to
	// be voted on. This happens when a record is censored or archived.
	VoteStatusIneligible VoteStatusT = 7

	// VoteStatusLast unit test only.
	VoteStatusLast VoteStatusT = 8
)

var (
	// VoteStatuses contains the human readable vote statuses.
	VoteStatuses = map[VoteStatusT]string{
		VoteStatusInvalid:      "invalid",
		VoteStatusUnauthorized: "unauthorized",
		VoteStatusAuthorized:   "authorized",
		VoteStatusStarted:      "started",
		VoteStatusFinished:     "finished",
		VoteStatusApproved:     "approved",
		VoteStatusRejected:     "rejected",
		VoteStatusIneligible:   "ineligible",
	}
)

// VoteMetadata that is specified by the user on record submission in order to
// host or participate in certain types of votes. It is attached to a record
// submission as a metadata stream.
type VoteMetadata struct {
	// LinkBy is set when the user intends for the record to be the
	// parent record in a runoff vote. It is a UNIX timestamp that
	// serves as the deadline for other records to declare their intent
	// to participate in the runoff vote.
	LinkBy int64 `json:"linkby,omitempty"`

	// LinkTo is the censorship token of a runoff vote parent record.
	// It is set when a record is being submitted as a vote options in
	// the runoff vote.
	LinkTo string `json:"linkto,omitempty"`
}

// VoteOption describes a single vote option.
type VoteOption struct {
	ID          string `json:"id"`          // Single, unique word (e.g. yes)
	Description string `json:"description"` // Longer description of the vote
	Bit         uint64 `json:"bit"`         // Bit used for this option
}

// VoteParams contains all client defined vote params required by server to
// start a record vote.
type VoteParams struct {
	Token    string `json:"token"`    // Record token
	Version  uint32 `json:"version"`  // Record version
	Type     VoteT  `json:"type"`     // Vote type
	Mask     uint64 `json:"mask"`     // Valid vote bits
	Duration uint32 `json:"duration"` // Duration in blocks

	// QuorumPercentage is the percent of elligible votes required for
	// the vote to meet a quorum.
	QuorumPercentage uint32 `json:"quorumpercentage"`

	// PassPercentage is the percent of cast votes required for a vote
	// option to be considered as passing.
	PassPercentage uint32 `json:"passpercentage"`

	Options []VoteOption `json:"options"`

	// Parent is the token of the parent record. This field will only
	// be populated for runoff votes.
	Parent string `json:"parent,omitempty"`
}

// StartDetails is the structure that is provided when starting a record
// vote.
//
// Signature is the signature of a SHA256 digest of the JSON encoded
// VoteParams.
type StartDetails struct {
	Params    VoteParams `json:"params"`
	PublicKey string     `json:"publickey"`
	Signature string     `json:"signature"`
}

// Start starts a record vote or multiple record votes if the vote is a runoff
// vote.
//
// Standard votes require that the vote have been authorized by the record
// author before an admin will able to start the voting process. The
// StartDetails list should only contain a single StartDetails.
//
// Runoff votes can be started by an admin at any point once the RFP link by
// deadline has expired. Runoff votes DO NOT require the votes to have been
// authorized by the submission authors prior to an admin starting the runoff
// vote. All public, non-abandoned RFP submissions should be included in the
// list of StartDetails.
type Start struct {
	Starts []StartDetails `json:"starts"`
}

// StartReply is the reply to the Start command.
//
// Receipt is the server signature of ClientSignature+StartBlockHash.
type StartReply struct {
	Receipt          string   `json:"receipt"`
	StartBlockHash   string   `json:"startblockhash"`
	StartBlockHeight uint32   `json:"startblockheight"`
	EndBlockHeight   uint32   `json:"endblockheight"`
	EligibleTickets  []string `json:"eligibletickets"`
}

// VoteErrorT represents an error that occurred while attempting to cast a
// ticket vote.
type VoteErrorT int

const (
	// VoteErrorInvalid is an invalid vote error.
	VoteErrorInvalid VoteErrorT = 0

	// VoteErrorInternalError is returned when an internal server error
	// occurred while attempting to cast a vote.
	VoteErrorInternalError VoteErrorT = 1

	// VoteErrorTokenInvalid is returned when a cast vote token is an
	// invalid record token.
	VoteErrorTokenInvalid VoteErrorT = 2

	// VoteErrorRecordNotFound is returned when a cast vote token does
	// not/correspond to a record.
	VoteErrorRecordNotFound VoteErrorT = 3

	// VoteErrorMultipleRecordVotes is returned when a ballot contains
	// cast votes for multiple records. A ballot can only contain votes
	// for a single record at a time.
	VoteErrorMultipleRecordVotes VoteErrorT = 4

	// VoteErrorVoteStatusInvalid is returned when a vote is cast on a record
	// that is not being actively voted on.
	VoteErrorVoteStatusInvalid VoteErrorT = 5

	// VoteErrorVoteBitInvalid is returned when a cast vote's vote bit
	// is not a valid vote option.
	VoteErrorVoteBitInvalid VoteErrorT = 6

	// VoteErrorSignatureInvalid is returned when a cast vote signature
	// is invalid.
	VoteErrorSignatureInvalid VoteErrorT = 7

	// VoteErrorTicketNotEligible is returned when attempting to cast
	// a vote using a dcr ticket that is not eligible.
	VoteErrorTicketNotEligible VoteErrorT = 8

	// VoteErrorTicketAlreadyVoted is returned when attempting to cast
	// a vote using a dcr ticket that has already voted.
	VoteErrorTicketAlreadyVoted VoteErrorT = 9
)

// CastVote is a signed ticket vote.
type CastVote struct {
	Token     string `json:"token"`     // Record token
	Ticket    string `json:"ticket"`    // Ticket ID
	VoteBit   string `json:"votebit"`   // Selected vote bit, hex encoded
	Signature string `json:"signature"` // Signature of Token+Ticket+VoteBit
}

// CastVoteReply contains the receipt for the cast vote.
type CastVoteReply struct {
	Ticket  string `json:"ticket"`  // Ticket ID
	Receipt string `json:"receipt"` // Server signature of client signature

	// The follwing fields will only be present if an error occurred
	// while attempting to cast the vote.
	ErrorCode    *VoteErrorT `json:"errorcode,omitempty"`
	ErrorContext string      `json:"errorcontext,omitempty"`
}

// CastBallot casts a ballot of votes. A ballot can only contain the votes for
// a single record.
type CastBallot struct {
	Votes []CastVote `json:"votes"`
}

// CastBallotReply is a reply to a batched list of votes.
type CastBallotReply struct {
	Receipts []CastVoteReply `json:"receipts"`
}

// AuthDetails contains the details of a vote authorization.
//
// Signature is the client signature of the Token+Version+Action.
type AuthDetails struct {
	Token     string `json:"token"`     // Record token
	Version   uint32 `json:"version"`   // Record version
	Action    string `json:"action"`    // Authorization or revoke
	PublicKey string `json:"publickey"` // Public key used for signature
	Signature string `json:"signature"` // Client signature
	Timestamp int64  `json:"timestamp"` // Server timestamp
	Receipt   string `json:"receipt"`   // Server sig of client sig
}

// VoteDetails contains the details of a record vote. A vote details with the
// eligible tickets snapshot will be ~0.35MB.
//
// Signature is the client signature of the SHA256 digest of the JSON encoded
// VoteParams struct.
//
// Receipt is the server signature of ClientSignature+StartBlockHash.
type VoteDetails struct {
	Params           VoteParams `json:"params"`
	PublicKey        string     `json:"publickey"`
	Signature        string     `json:"signature"`
	Receipt          string     `json:"receipt"`
	StartBlockHeight uint32     `json:"startblockheight"`
	StartBlockHash   string     `json:"startblockhash"`
	EndBlockHeight   uint32     `json:"endblockheight"`
	EligibleTickets  []string   `json:"eligibletickets"` // Ticket hashes
}

// Details requests the vote details for a record vote.
type Details struct {
	Token string `json:"token"`
}

// DetailsReply is the reply to the Details command.
type DetailsReply struct {
	Auths []AuthDetails `json:"auths"`
	Vote  *VoteDetails  `json:"vote"`
}

// CastVoteDetails contains the details of a cast vote.
//
// Signature is the client signature of the Token+Ticket+VoteBit. The client
// uses the ticket's largest commitment address to create the signature. The
// receipt is the server signature of the client signature.
type CastVoteDetails struct {
	Token     string `json:"token"`     // Record token
	Ticket    string `json:"ticket"`    // Ticket hash
	VoteBit   string `json:"votebit"`   // Selected vote bit, hex encoded
	Address   string `json:"address"`   // Address used in client signature
	Signature string `json:"signature"` // Client signature
	Receipt   string `json:"receipt"`   // Server sig of client sig
	Timestamp int64  `json:"timestamp"` // Unix timestamp
}

// Results returns the cast votes for a record.
type Results struct {
	Token string `json:"token"`
}

// ResultsReply is the reply to the Results command.
type ResultsReply struct {
	Votes []CastVoteDetails `json:"votes"`
}

// VoteResult describes a vote option and the total number of votes that have
// been cast for this option.
type VoteResult struct {
	ID          string `json:"id"`          // Single unique word (e.g. yes)
	Description string `json:"description"` // Longer description of the vote
	VoteBit     uint64 `json:"votebit"`     // Bits used for this option
	Votes       uint64 `json:"votes"`       // Votes cast for this option
}

// Summary summarizes the vote params and results of a record vote.
type Summary struct {
	Type             VoteT       `json:"type"`
	Status           VoteStatusT `json:"status"`
	Duration         uint32      `json:"duration"` // In blocks
	StartBlockHeight uint32      `json:"startblockheight"`
	StartBlockHash   string      `json:"startblockhash"`
	EndBlockHeight   uint32      `json:"endblockheight"`

	// EligibleTickets is the number of tickets that are eligible to
	// cast a vote.
	EligibleTickets uint32 `json:"eligibletickets"`

	// QuorumPercentage is the percent of eligible tickets required to
	// vote in order to have a quorum.
	QuorumPercentage uint32 `json:"quorumpercentage"`

	// PassPercentage is the percent of cast votes required for a vote
	// option to be considered as passing.
	PassPercentage uint32 `json:"passpercentage"`

	Results []VoteResult `json:"results"`

	// BestBlock is the best block value that was used to prepare the
	// summary.
	BestBlock uint32 `json:"bestblock"`
}

const (
	// SummariesPageSize is the maximum number of vote summaries that
	// can be requested at any one time.
	SummariesPageSize uint32 = 5
)

// Summaries requests the vote summaries for the provided record tokens.
type Summaries struct {
	Tokens []string `json:"tokens"`
}

// SummariesReply is the reply to the Summaries command.
//
// Summaries field contains a vote summary for each of the provided tokens.
// The map will not contain an entry for any tokens that did not correspond
// to an actual record. It is the callers responsibility to ensure that a
// summary is returned for all provided tokens.
type SummariesReply struct {
	Summaries map[string]Summary `json:"summaries"` // [token]Summary
}

// Submissions requests the submissions of a runoff vote. The only records
// that will have a submissions list are the parent records in a runoff vote.
// The list will contain all public runoff vote submissions, i.e. records that
// have linked to the parent record using the VoteMetadata LinkTo field.
type Submissions struct {
	Token string `json:"token"`
}

// SubmissionsReply is the reply to the Submissions command.
type SubmissionsReply struct {
	Submissions []string `json:"submissions"`
}

const (
	// InventoryPageSize is the maximum number of tokens that will be
	// returned for any single status in an InventoryReply.
	InventoryPageSize uint32 = 20
)

// Inventory requests the tokens of public records in the inventory
// categorized by vote status.
//
// The status and page arguments can be provided to request a specific page of
// record tokens.
//
// If no status is provided then a page of tokens for all statuses will be
// returned. The page argument will be ignored.
type Inventory struct {
	Status VoteStatusT `json:"status,omitempty"`
	Page   uint32      `json:"page,omitempty"`
}

// InventoryReply is the reply to the Inventory command. The returned map is a
// map[votestatus][]token where the votestatus key is the human readable vote
// status defined by the VoteStatuses array in this package.
//
// Sorted by timestamp newest to oldest:
// Unauthorized, Authorized
//
// Sorted by vote start block height in descending order:
// Started
//
// Sorted by vote end block height in descending order:
// Finished, Approved, Rejected
type InventoryReply struct {
	Vetted map[string][]string `json:"vetted"`

	// BestBlock is the best block value that was used to prepare the
	// inventory.
	BestBlock uint32 `json:"bestblock"`
}

// Proof contains an inclusion proof for the digest in the merkle root. All
// digests are hex encoded SHA256 digests.
//
// The ExtraData field is used by certain types of proofs to include additional
// data that is required to validate the proof.
type Proof struct {
	Type       string   `json:"type"`
	Digest     string   `json:"digest"`
	MerkleRoot string   `json:"merkleroot"`
	MerklePath []string `json:"merklepath"`
	ExtraData  string   `json:"extradata"` // JSON encoded
}

// Timestamp contains all of the data required to verify that a piece of data
// was timestamped onto the decred blockchain.
//
// All digests are hex encoded SHA256 digests. The merkle root can be found in
// the OP_RETURN of the specified DCR transaction.
//
// TxID, MerkleRoot, and Proofs will only be populated once the merkle root has
// been included in a DCR tx and the tx has 6 confirmations. The Data field
// will not be populated if the data has been censored.
type Timestamp struct {
	Data       string  `json:"data"` // JSON encoded
	Digest     string  `json:"digest"`
	TxID       string  `json:"txid"`
	MerkleRoot string  `json:"merkleroot"`
	Proofs     []Proof `json:"proofs"`
}

const (
	// VoteTimestampsPageSize is the maximum number of vote timestamps
	// that will be returned for any single request.
	VoteTimestampsPageSize uint32 = 100
)

// Timestamps requests the timestamps for ticket vote data.
//
// If no votes page number is provided then the vote authorization and vote
// details timestamps will be returned. If a votes page number is provided
// then the specified page of cast vote timestamps will be returned.
type Timestamps struct {
	Token     string `json:"token"`
	VotesPage uint32 `json:"votespage,omitempty"`
}

// TimestampsReply is the reply to the Timestamps command.
type TimestampsReply struct {
	// Auths contains the timestamps for vote authorizations. The data
	// payloads will contain AuthDetails structures.
	Auths []Timestamp `json:"auths,omitempty"`

	// Details contains the timestamps for the vote details. The data
	// payload will contain a VoteDetails structure.
	Details *Timestamp `json:"details,omitempty"`

	// Votes contains the timestamps for the cast votes. The data
	// payloads will contain CastVoteDetails strucutures.
	Votes []Timestamp `json:"votes,omitempty"`
}
