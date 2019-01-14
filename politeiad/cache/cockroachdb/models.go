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

// TODO: index Comments by Token
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

// TODO: index LikeComments by PublicKey and by token
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
