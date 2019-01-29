// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cockroachdb

// Version is the version of the cache the database is using.
type Version struct {
	Key       uint   `gorm:"primary_key"` // Primary key
	Version   uint32 `gorm:"not null"`    // Cache version
	Timestamp int64  `gorm:"not null"`    // UNIX timestamp of record creation
}

// TableName returns the name of the Version database table.
func (Version) TableName() string {
	return tableVersion
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
	Key       string `gorm:"primary_key"`       // Primary key (token+version)
	Token     string `gorm:"not null;size:64"`  // Censorship token
	Version   string `gorm:"not null"`          // Version of files
	Status    int    `gorm:"not null"`          // Current status
	Timestamp int64  `gorm:"not null"`          // UNIX timestamp of last updated
	Merkle    string `gorm:"not null;size:64"`  // Merkle root of all files in record
	Signature string `gorm:"not null;size:128"` // Server signature of merkle+token

	Metadata []MetadataStream `gorm:"foreignkey:RecordKey"` // User provided metadata
	Files    []File           `gorm:"foreignkey:RecordKey"` // User provided files
}

// TableName returns the name of the Record database table.
func (Record) TableName() string {
	return tableRecords
}

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

func (Comment) TableName() string {
	return tableComments
}

type LikeComment struct {
	Key       uint   `gorm:"primary_key"`       // Primary key
	Token     string `gorm:"not null;size:64"`  // Censorship token
	CommentID string `gorm:"not null"`          // Comment ID
	Action    string `gorm:"not null;size:2"`   // Up or downvote (1, -1)
	Signature string `gorm:"not null;size:128"` // Client Signature of Token+CommentID+Action
	PublicKey string `gorm:"not null;size:64"`  // Public key used for Signature
	Receipt   string `gorm:"not null;size:128"` // Signature of Signature
	Timestamp int64  `gorm:"not null"`          // Received UNIX timestamp
}

func (LikeComment) TableName() string {
	return tableCommentLikes
}

type AuthorizeVote struct {
	Key       string `gorm:"primary_key"`       // Primary key (token+version)
	Token     string `gorm:"not null;size:64"`  // Censorship token
	Version   string `gorm:"not null"`          // Version of files
	Action    string `gorm:"not null"`          // Authorize or revoke
	Signature string `gorm:"not null;size:128"` // Signature of token+version+action
	PublicKey string `gorm:"not null;size:64"`  // Pubkey used for signature
	Receipt   string `gorm:"not null;size:128"` // Server signature of client signature
	Timestamp int64  `gorm:"not null"`          // Received UNIX timestamp
}

func (AuthorizeVote) TableName() string {
	return tableAuthorizeVotes
}

type VoteOption struct {
	Key         uint   `gorm:"primary_key"`      // Primary key
	Token       string `gorm:"not null;size:64"` // StartVote foreign key
	ID          string `gorm:"not null"`         // Single unique word identifying vote (e.g. yes)
	Description string `gorm:"not null"`         // Longer description of the vote
	Bits        uint64 `gorm:"not null"`         // Bits used for this option
}

func (VoteOption) TableName() string {
	return tableVoteOptions
}

type StartVote struct {
	Token            string       `gorm:"primary_key;size:64"` // Censorship token
	Version          string       `gorm:"not null"`            // Version of files
	Mask             uint64       `gorm:"not null"`            // Valid votebits
	Duration         uint32       `gorm:"not null"`            // Duration in blocks
	QuorumPercentage uint32       `gorm:"not null"`            // Percent of eligible votes required for quorum
	PassPercentage   uint32       `gorm:"not null"`            // Percent of total votes required to pass
	Options          []VoteOption `gorm:"foreignkey:Token"`    // Vote option
	PublicKey        string       `gorm:"not null;size:64"`    // Key used for signature
	Signature        string       `gorm:"not null;size:128"`   // Signature of Votehash
	StartBlockHeight string       `gorm:"not null"`            // Block height
	StartBlockHash   string       `gorm:"not null"`            // Block hash
	EndHeight        string       `gorm:"not null"`            // Height of vote end
	EligibleTickets  string       `gorm:"not null"`            // Valid voting tickets
}

func (StartVote) TableName() string {
	return tableStartVotes
}

type CastVote struct {
	Key       uint   `gorm:"primary_key"`       // Primary key
	Token     string `gorm:"not null;size:64"`  // Censorship token
	Ticket    string `gorm:"not null"`          // Ticket ID
	VoteBit   string `gorm:"not null"`          // Vote bit that was selected, this is encode in hex
	Signature string `gorm:"not null;size:130"` // Signature of Token+Ticket+VoteBit
	Receipt   string `gorm:"not null;size:128"` // Server signature of client signature
}

func (CastVote) TableName() string {
	return tableCastVotes
}
