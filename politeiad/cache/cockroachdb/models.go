// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cockroachdb

// Version describes the version of a record or plugin that the database is
// currently using.
type Version struct {
	ID        string `gorm:"primary_key"` // Primary key
	Version   string `gorm:"not null"`    // Version
	Timestamp int64  `gorm:"not null"`    // UNIX timestamp of record creation
}

// TableName returns the name of the Version database table.
func (Version) TableName() string {
	return tableVersions
}

// File describes an individual file that is part of the record.
type File struct {
	Key       uint   `gorm:"primary_key"`      // Primary key
	RecordKey string `gorm:"not null"`         // Record foreign key
	Name      string `gorm:"not null"`         // Basename of the file
	MIME      string `gorm:"not null"`         // MIME type
	Digest    string `gorm:"not null;size:64"` // SHA256 of decoded Payload
	Payload   string `gorm:"not null"`         // base64 encoded file
}

// TableName returns the name of the File database table.
func (File) TableName() string {
	return tableFiles
}

// MetadataStream identifies a metadata stream by its identity.
type MetadataStream struct {
	Key       uint   `gorm:"primary_key"` // Primary key
	RecordKey string `gorm:"not null"`    // Record foreign key
	ID        uint64 `gorm:"not null"`    // Stream identity
	Payload   string `gorm:"not null"`    // String encoded metadata
}

// TableName returns the name of the MetadataStream database table.
func (MetadataStream) TableName() string {
	return tableMetadataStreams
}

// Record is an entire record and it's content.
type Record struct {
	Key         string `gorm:"primary_key"`           // Primary key (token+version)
	Token       string `gorm:"not null;size:64"`      // Censorship token
	TokenPrefix string `gorm:"not null;size:6;index"` // Prefix of token used for lookups
	Version     uint64 `gorm:"not null"`              // Version of files
	Status      int    `gorm:"not null"`              // Current status
	Timestamp   int64  `gorm:"not null"`              // UNIX timestamp of last updated
	Merkle      string `gorm:"not null;size:64"`      // Merkle root of all files in record
	Signature   string `gorm:"not null;size:128"`     // Server signature of merkle+token

	Metadata []MetadataStream `gorm:"foreignkey:RecordKey"` // User provided metadata
	Files    []File           `gorm:"foreignkey:RecordKey"` // User provided files
}

// TableName returns the name of the Record database table.
func (Record) TableName() string {
	return tableRecords
}

// ProposalGeneralMetadata represents general medadata for a proposal.
//
// This mdstream data is already saved to the cache as a MetadataStream with an
// encoded payload. The ProposalGeneralMetadata duplicates existing data, but
// is necessary so that the metadata fields can be queried, which is not
// possible with the encoded MetadataStream payload. ProposalGeneralMetadata
// is only saved for the most recent proposal version since this is the only
// metadata that currently needs to be queried.
//
// This is a decred plugin model.
type ProposalGeneralMetadata struct {
	Token           string `gorm:"primary_key;size:64"` // Censorship token
	ProposalVersion uint64 `gorm:"not null"`            // Proposal version
	Version         uint64 `gorm:"not null"`            // Struct version
	Timestamp       int64  `gorm:"not null"`            // Last update of proposal
	Name            string `gorm:"not null"`            // Proposal name
	Signature       string `gorm:"not null;size:128"`   // Client signature
	PublicKey       string `gorm:"not null;size:64"`    // Pubkey used for Signature
}

// Comment represents a record comment, including all of the server side
// metadata.
//
// This is a decred plugin model.
type Comment struct {
	Key       string `gorm:"primary_key"`       // Primary key (token+commentID)
	Token     string `gorm:"not null;size:64"`  // Censorship token
	ParentID  string `gorm:"not null"`          // Parent comment ID
	Comment   string `gorm:"not null"`          // Comment
	Signature string `gorm:"not null;size:128"` // Client Signature of Token+ParentID+Comment
	PublicKey string `gorm:"not null;size:64"`  // Pubkey used for Signature
	CommentID string `gorm:"not null"`          // Comment ID
	Receipt   string `gorm:"not null"`          // Server signature of the client Signature
	Timestamp int64  `gorm:"not null"`          // Received UNIX timestamp
	Censored  bool   `gorm:"not null"`          // Has this comment been censored
}

// TableName returns the name of the Comment database table.
func (Comment) TableName() string {
	return tableComments
}

// LikeComment describes a comment upvote/downvote.  The server side metadata
// is not included.
//
// This is a decred plugin model.
type LikeComment struct {
	Key       uint   `gorm:"primary_key"`       // Primary key
	Token     string `gorm:"not null;size:64"`  // Censorship token
	CommentID string `gorm:"not null"`          // Comment ID
	Action    string `gorm:"not null;size:2"`   // Up or downvote (1, -1)
	Signature string `gorm:"not null;size:128"` // Client Signature of Token+CommentID+Action
	PublicKey string `gorm:"not null;size:64"`  // Public key used for Signature
}

// TableName returns the name of the LikeComment database table.
func (LikeComment) TableName() string {
	return tableCommentLikes
}

// AuthorizeVote is used to indicate that a record has been finalized and is
// ready to be voted on.
//
// This is a decred plugin model.
type AuthorizeVote struct {
	Key       string `gorm:"primary_key"`       // Primary key (token+version)
	Token     string `gorm:"not null;size:64"`  // Censorship token
	Version   uint64 `gorm:"not null"`          // Version of files
	Action    string `gorm:"not null"`          // Authorize or revoke
	Signature string `gorm:"not null;size:128"` // Signature of token+version+action
	PublicKey string `gorm:"not null;size:64"`  // Pubkey used for signature
	Receipt   string `gorm:"not null;size:128"` // Server signature of client signature
	Timestamp int64  `gorm:"not null"`          // Received UNIX timestamp
}

// TableName returns the name of the AuthorizeVote database table.
func (AuthorizeVote) TableName() string {
	return tableAuthorizeVotes
}

// VoteOption describes a single vote option.
//
// This is a decred plugin model.
type VoteOption struct {
	Key         uint   `gorm:"primary_key"`      // Primary key
	Token       string `gorm:"not null;size:64"` // StartVote foreign key
	ID          string `gorm:"not null"`         // Single unique word identifying vote (e.g. yes)
	Description string `gorm:"not null"`         // Longer description of the vote
	Bits        uint64 `gorm:"not null"`         // Bits used for this option
}

// TableName returns the name of the VoteOption database table.
func (VoteOption) TableName() string {
	return tableVoteOptions
}

// StartVote records the details of a proposal vote.
//
// ProposalVersion will only be present when StartVote version is >= 2 since
// the decredplugin VoteV1 struct does not contain the proposal version.
//
// QuorumPercentage is the percent of eligible votes required for a quorum.
//
// PassPercentage is the percent of total votes required for the proposal to
// be considered approved.
//
// The data contained in the cache StartVote includes the decredplugin
// StartVote and StartVoteReply mdstreams. These mdstreams are not saved in the
// cache as separate Record.Metadata for the given proposal. This means that
// this mdstream data will not be returned when a proposal record is fetched
// from the cache. The cache StartVote must be queried directly to obtain this
// data.
//
// This is a decred plugin model.
type StartVote struct {
	Token               string       `gorm:"primary_key;size:64"` // Censorship token
	Version             uint         `gorm:"not null"`            // StartVote struct version
	ProposalVersion     uint32       ``                           // Prop version being voted on
	Type                int          `gorm:"not null"`            // Vote type
	Mask                uint64       `gorm:"not null"`            // Valid votebits
	Duration            uint32       `gorm:"not null"`            // Duration in blocks
	QuorumPercentage    uint32       `gorm:"not null"`            // Quorum requirement
	PassPercentage      uint32       `gorm:"not null"`            // Approval requirement
	Options             []VoteOption `gorm:"foreignkey:Token"`    // Vote option
	PublicKey           string       `gorm:"not null;size:64"`    // Key used for signature
	Signature           string       `gorm:"not null;size:128"`   // Signature
	StartBlockHeight    uint32       `gorm:"not null"`            // Block height
	StartBlockHash      string       `gorm:"not null"`            // Block hash
	EndHeight           uint32       `gorm:"not null"`            // Height of vote end
	EligibleTickets     string       `gorm:"not null"`            // Valid voting tickets
	EligibleTicketCount int          `gorm:"not null"`            // Number of eligible tickets
}

// TableName returns the name of the StartVote database table.
func (StartVote) TableName() string {
	return tableStartVotes
}

// CastVote records a signed vote.
//
// This is a decred plugin model.
type CastVote struct {
	Key       uint   `gorm:"primary_key"`       // Primary key
	Token     string `gorm:"not null;size:64"`  // Censorship token
	Ticket    string `gorm:"not null"`          // Ticket ID
	VoteBit   string `gorm:"not null"`          // Hex encoded vote bit that was selected
	Signature string `gorm:"not null;size:130"` // Signature of Token+Ticket+VoteBit

	// TokenVoteBit is the Token+VoteBit. Indexing TokenVoteBit allows
	// for quick lookups of the number of votes cast for each vote bit.
	TokenVoteBit string `gorm:"no null;index"`
}

// TableName returns the name of the CastVote database table.
func (CastVote) TableName() string {
	return tableCastVotes
}

// VoteOptionResults records the vote result for a vote option. A
// VoteOptionResult should only be created once the proposal vote has finished.
//
// This is a decred plugin model.
type VoteOptionResult struct {
	Key       string     `gorm:"primary_key"`      // Primary key (token+votebit)
	Token     string     `gorm:"not null;size:64"` // Censorship token (VoteResults foreign key)
	Votes     uint64     `gorm:"not null"`         // Number of votes cast for this option
	Option    VoteOption `gorm:"not null"`         // Vote option
	OptionKey uint       `gorm:"not null"`         // VoteOption foreign key
}

// TableName returns the name of the VoteOptionResult database table.
func (VoteOptionResult) TableName() string {
	return tableVoteOptionResults
}

// VoteResults records the tallied vote results for a proposal and whether the
// vote was approved/rejected.  A vote result entry should only be created once
// the voting period has ended.  The vote results table is lazy loaded.
//
// This is a decred plugin model.
type VoteResults struct {
	Token    string             `gorm:"primary_key;size:64"` // Censorship token
	Approved bool               `gorm:"not null"`            // Vote was approved
	Results  []VoteOptionResult `gorm:"foreignkey:Token"`    // Results for the vote options
}

// TableName returns the name of the VoteResults database table.
func (VoteResults) TableName() string {
	return tableVoteResults
}
