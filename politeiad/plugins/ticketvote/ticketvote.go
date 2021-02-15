// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package ticketvote provides a plugin for running votes that require decred
// tickets to participate.
package ticketvote

const (
	// PluginID is the ticketvote plugin ID.
	PluginID = "ticketvote"

	// Plugin commands
	CmdAuthorize   = "authorize"   // Authorize a vote
	CmdStart       = "start"       // Start a vote
	CmdCastBallot  = "castballot"  // Cast a ballot of votes
	CmdDetails     = "details"     // Get vote details
	CmdResults     = "results"     // Get vote results
	CmdSummary     = "summary"     // Get vote summary
	CmdSubmissions = "submissions" // Get runoff vote submissions
	CmdInventory   = "inventory"   // Get inventory by vote status
	CmdTimestamps  = "timestamps"  // Get vote data timestamps

	// Setting keys are the plugin setting keys that can be used to
	// override a default plugin setting. Defaults will be overridden
	// if a plugin setting is provided to the plugin on startup.
	SettingKeyLinkByPeriodMin = "linkbyperiodmin"
	SettingKeyLinkByPeriodMax = "linkbyperiodmax"
	SettingKeyVoteDurationMin = "votedurationmin"
	SettingKeyVoteDurationMax = "votedurationmax"

	// SettingLinkByPeriodMin is the default minimum amount of time,
	// in seconds, that the link by period can be set to. This value
	// of 2 weeks was chosen assuming a 1 week voting period on
	// mainnet.
	SettingLinkByPeriodMin int64 = 1209600

	// SettingLinkByPeriodMax is the default maximum amount of time,
	// in seconds, that the link by period can be set to. This value
	// of 3 months was chosen arbitrarily.
	SettingLinkByPeriodMax int64 = 7776000

	// SettingMainNetVoteDurationMin is the default minimum vote
	// duration on mainnet in blocks.
	SettingMainNetVoteDurationMin uint32 = 2016

	// SettingMainNetVoteDurationMax is the default maximum vote
	// duration on mainnet in blocks.
	SettingMainNetVoteDurationMax uint32 = 4032

	// SettingTestNetVoteDurationMin is the default minimum vote
	// duration on testnet in blocks.
	SettingTestNetVoteDurationMin uint32 = 1

	// SettingTestNetVoteDurationMax is the default maximum vote
	// duration on testnet in blocks.
	SettingTestNetVoteDurationMax uint32 = 4032

	// SettingSimNetVoteDurationMin is the default minimum vote
	// duration on simnet in blocks.
	SettingSimNetVoteDurationMin uint32 = 1

	// SettingSimNetVoteDurationMax is the default maximum vote
	// duration on simnet in blocks.
	SettingSimNetVoteDurationMax uint32 = 4032
)

// ErrorCodeT represents and error that is caused by the user.
type ErrorCodeT int

const (
	ErrorCodeInvalid                 ErrorCodeT = 0
	ErrorCodeTokenInvalid            ErrorCodeT = 1
	ErrorCodePublicKeyInvalid        ErrorCodeT = 2
	ErrorCodeSignatureInvalid        ErrorCodeT = 3
	ErrorCodeRecordVersionInvalid    ErrorCodeT = 4
	ErrorCodeRecordStatusInvalid     ErrorCodeT = 5
	ErrorCodeAuthorizationInvalid    ErrorCodeT = 6
	ErrorCodeStartDetailsMissing     ErrorCodeT = 7
	ErrorCodeStartDetailsInvalid     ErrorCodeT = 8
	ErrorCodeVoteParamsInvalid       ErrorCodeT = 9
	ErrorCodeVoteStatusInvalid       ErrorCodeT = 10
	ErrorCodePageSizeExceeded        ErrorCodeT = 11
	ErrorCodeVoteMetadataInvalid     ErrorCodeT = 12
	ErrorCodeLinkByInvalid           ErrorCodeT = 13
	ErrorCodeLinkToInvalid           ErrorCodeT = 14
	ErrorCodeRunoffVoteParentInvalid ErrorCodeT = 15
	ErrorCodeLinkByNotExpired        ErrorCodeT = 16
)

var (
	// ErrorCodes contains the human readable error messages.
	ErrorCodes = map[ErrorCodeT]string{
		ErrorCodeInvalid:                 "error code invalid",
		ErrorCodeTokenInvalid:            "token invalid",
		ErrorCodePublicKeyInvalid:        "public key invalid",
		ErrorCodeSignatureInvalid:        "signature invalid",
		ErrorCodeRecordVersionInvalid:    "record version invalid",
		ErrorCodeRecordStatusInvalid:     "record status invalid",
		ErrorCodeAuthorizationInvalid:    "authorization invalid",
		ErrorCodeStartDetailsMissing:     "start details missing",
		ErrorCodeStartDetailsInvalid:     "start details invalid",
		ErrorCodeVoteParamsInvalid:       "vote params invalid",
		ErrorCodeVoteStatusInvalid:       "vote status invalid",
		ErrorCodePageSizeExceeded:        "page size exceeded",
		ErrorCodeVoteMetadataInvalid:     "vote metadata invalid",
		ErrorCodeLinkByInvalid:           "linkby invalid",
		ErrorCodeLinkToInvalid:           "linkto invalid",
		ErrorCodeRunoffVoteParentInvalid: "runoff vote parent invalid",
		ErrorCodeLinkByNotExpired:        "linkby not exipred",
	}
)

const (
	// FileNameVoteMetadata is the filename of the VoteMetadata file
	// that is saved to politeiad. VoteMetadata is saved to politeiad
	// as a file, not as a metadata stream, since it contains user
	// provided metadata and needs to be included in the merkle root
	// that politeiad signs.
	FileNameVoteMetadata = "votemetadata.json"
)

// VoteMetadata is metadata that is specified by the user and attached to
// a record on submission. This metadata is required for certain types of
// votes.
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

// AuthDetails is the structure that is saved to disk when a vote is authorized
// or a previous authorization is revoked. It contains all the fields from a
// Authorize and a AuthorizeReply.
type AuthDetails struct {
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

// VoteT represents the different types of ticket votes that are available.
type VoteT int

const (
	// VoteTypeInvalid is an invalid vote type.
	VoteTypeInvalid VoteT = 0

	// VoteTypeStandard is used to indicate a simple approve or reject
	// vote where the winner is the voting option that has met the
	// specified quorum and pass requirements. Standard votes must be
	// authorized before the vote can be started.
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
	// net yes votes. Runoff vote participants are not required to have
	// the voting period authorized prior to the vote starting.
	VoteTypeRunoff VoteT = 2
)

const (
	// VoteOptionIDApprove is the vote option ID that indicates the vote
	// should be approved. Votes that are an approve/reject vote are
	// required to use this vote option ID.
	VoteOptionIDApprove = "yes"

	// VoteOptionIDReject is the vote option ID that indicates the vote
	// should be not be approved. Votes that are an approve/reject vote
	// are required to use this vote option ID.
	VoteOptionIDReject = "no"
)

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

	// Parent is the token of the parent record. This field will only
	// be populated for runoff votes.
	Parent string `json:"parent,omitempty"`
}

// VoteDetails is the structure that is saved to disk when a vote is started.
// It contains all of the fields from a Start and a StartReply.
//
// Signature is the client signature of the SHA256 digest of the JSON encoded
// Vote struct.
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
type CastVoteDetails struct {
	// Data generated by client
	Token     string `json:"token"`     // Record token
	Ticket    string `json:"ticket"`    // Ticket hash
	VoteBit   string `json:"votebits"`  // Selected vote bit, hex encoded
	Signature string `json:"signature"` // Signature of Token+Ticket+VoteBit

	// Metdata generated by server
	Receipt string `json:"receipt"` // Server signature of client signature
}

// AuthActionT represents the ticket vote authorization actions.
type AuthActionT string

const (
	// AuthActionAuthorize is used to authorize a ticket vote.
	AuthActionAuthorize AuthActionT = "authorize"

	// AuthActionRevoke is used to revoke a previous ticket vote
	// authorization.
	AuthActionRevoke AuthActionT = "revoke"
)

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

// AuthorizeReply is the reply to the Authorize command.
type AuthorizeReply struct {
	Timestamp int64  `json:"timestamp"` // Received UNIX timestamp
	Receipt   string `json:"receipt"`   // Server signature of client signature
}

// StartDetails is the structure that is provided when starting a ticket vote.
//
// Signature is the signature of a SHA256 digest of the JSON encoded VoteParams
// structure.
type StartDetails struct {
	Params    VoteParams `json:"params"`
	PublicKey string     `json:"publickey"` // Public key used for signature
	Signature string     `json:"signature"` // Client signature
}

// Start starts a ticket vote.
type Start struct {
	Starts []StartDetails `json:"starts"`
}

// StartReply is the reply to the Start command.
type StartReply struct {
	StartBlockHeight uint32   `json:"startblockheight"`
	StartBlockHash   string   `json:"startblockhash"`
	EndBlockHeight   uint32   `json:"endblockheight"`
	EligibleTickets  []string `json:"eligibletickets"`
}

// VoteErrorT represents errors that can occur while attempting to cast ticket
// votes.
type VoteErrorT int

const (
	// VoteErrorInvalid is an invalid vote error.
	VoteErrorInvalid VoteErrorT = 0

	// VoteErrorInternalError is returned when an internal server error
	// occurred.
	VoteErrorInternalError VoteErrorT = 1

	// VoteErrorTokenInvalid is returned when the record censorship
	// token is invalid.
	VoteErrorTokenInvalid VoteErrorT = 2

	// VoteErrorRecordNotFound is returned when the specified record
	// does not exist.
	VoteErrorRecordNotFound VoteErrorT = 3

	// VoteErrorMultipleRecordVotes is returned when votes are casts
	// for multiple records in a single ballot.
	VoteErrorMultipleRecordVotes VoteErrorT = 4

	// VoteErrorVoteStatusInvalid is returned when the ticket vote
	// status does not allow for votes to be cast, such as when a vote
	// has already finished.
	VoteErrorVoteStatusInvalid VoteErrorT = 5

	// VoteErrorVoteBitInvalid is returned when the vote being cast
	// uses invalid vote bits.
	VoteErrorVoteBitInvalid VoteErrorT = 6

	// VoteErrorSignatureInvalid is returned when the vote being cast
	// has an invalid signature.
	VoteErrorSignatureInvalid VoteErrorT = 7

	// VoteErrorTicketNotEligible is returned when a vote is being cast
	// using a ticket that is not part of the vote.
	VoteErrorTicketNotEligible VoteErrorT = 8

	// VoteErrorTicketAlreadyVoted is returned when a vote is cast
	// using a ticket that has already voted.
	VoteErrorTicketAlreadyVoted VoteErrorT = 9
)

var (
	// VoteErrors contains the human readable error messages for the
	// vote errors.
	VoteErrors = map[VoteErrorT]string{
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
)

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

// CastBallot casts a ballot of votes. A ballot can only contain votes for a
// single record.
type CastBallot struct {
	Ballot []CastVote `json:"ballot"`
}

// CastBallotReply is a reply to a batched list of votes.
type CastBallotReply struct {
	Receipts []CastVoteReply `json:"receipts"`
}

// Details returns the vote details for a record.
type Details struct{}

// DetailsReply is the reply to the Details command.
type DetailsReply struct {
	Auths []AuthDetails `json:"auths"`
	Vote  *VoteDetails  `json:"vote"`
}

// Results requests the results of a vote.
type Results struct{}

// ResultsReply is the rely to the Results command.
type ResultsReply struct {
	Votes []CastVoteDetails `json:"votes"`
}

// VoteStatusT represents the status of a ticket vote.
type VoteStatusT int

const (
	// VoteStatusInvalid is an invalid vote status.
	VoteStatusInvalid VoteStatusT = 0

	// VoteStatusUnauthorized indicates the ticket vote has not been
	// authorized yet.
	VoteStatusUnauthorized VoteStatusT = 1

	// VoteStatusAuthorized indicates the ticket vote has been
	// authorized.
	VoteStatusAuthorized VoteStatusT = 2

	// VoteStatusStarted indicates the ticket vote has been started.
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
	}
)

// VoteOptionResult describes a vote option and the total number of votes that
// have been cast for this option.
type VoteOptionResult struct {
	ID          string `json:"id"`          // Single unique word (e.g. yes)
	Description string `json:"description"` // Longer description of the vote
	VoteBit     uint64 `json:"votebit"`     // Bits used for this option
	Votes       uint64 `json:"votes"`       // Votes cast for this option
}

// Summary requests the vote summaries for a record.
type Summary struct{}

// SummaryReply is the reply to the Summary command.
type SummaryReply struct {
	Type             VoteT              `json:"type"`
	Status           VoteStatusT        `json:"status"`
	Duration         uint32             `json:"duration"`
	StartBlockHeight uint32             `json:"startblockheight"`
	StartBlockHash   string             `json:"startblockhash"`
	EndBlockHeight   uint32             `json:"endblockheight"`
	EligibleTickets  uint32             `json:"eligibletickets"`
	QuorumPercentage uint32             `json:"quorumpercentage"`
	PassPercentage   uint32             `json:"passpercentage"`
	Results          []VoteOptionResult `json:"results"`

	// BestBlock is the best block value that was used to prepare this
	// summary.
	BestBlock uint32 `json:"bestblock"`
}

// Submissions requests the submissions of a runoff vote. The only records that
// will have a submissions list are the parent records in a runoff vote. The
// list will contain all public runoff vote submissions, i.e. records that
// have linked to the parent record using the VoteMetadata.LinkTo field.
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

// Inventory requests the tokens of public records in the inventory categorized
// by vote status.
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
// Sorted by timestamp in descending order:
// Unauthorized, Authorized
//
// Sorted by vote start block height in descending order:
// Started
//
// Sorted by vote end block height in descending order:
// Finished, Approved, Rejected
type InventoryReply struct {
	Tokens map[string][]string `json:"tokens"`

	// BestBlock is the best block value that was used to prepare the
	// inventory.
	BestBlock uint32 `json:"bestblock"`
}

// Proof contains an inclusion proof for the digest in the merkle root. The
// ExtraData field is used by certain types of proofs to include additional
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

// Timestamps requests the timestamps for ticket vote data.
type Timestamps struct{}

// TimestampsReply is the reply to the Timestamps command.
type TimestampsReply struct {
	Auths   []Timestamp          `json:"auths,omitempty"`
	Details Timestamp            `json:"details,omitempty"`
	Votes   map[string]Timestamp `json:"votes,omitempty"` // [ticket]Timestamp
}
