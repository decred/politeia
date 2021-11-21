// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package usermd provides a politeiad plugin that extends records with user
// metadata and provides an API for retrieving records by user metadata.
package usermd

const (
	// PluginID is the unique identifier for this plugin.
	PluginID = "usermd"

	// CmdAuthor gets record author
	CmdAuthor = "author"

	// CmdUserRecords gets user submitted records
	CmdUserRecords = "userrecords"
)

// Stream IDs are the metadata stream IDs for metadata defined in this package.
const (
	// StreamIDUserMetadata is the politeiad metadata stream ID for the
	// UserMetadata structure.
	StreamIDUserMetadata uint32 = 1

	// StreamIDStatusChanges is the politeiad metadata stream ID for
	// the status changes metadata. Status changes are appended onto
	// this metadata stream.
	StreamIDStatusChanges uint32 = 2
)

// ErrorCodeT represents a plugin error that was caused by the user.
type ErrorCodeT uint32

const (
	// ErrorCodeInvalid is an invalid error code.
	ErrorCodeInvalid ErrorCodeT = 0

	// ErrorCodeUserMetadataNotFound is returned when a record does
	// not contain a metdata stream for user metadata.
	ErrorCodeUserMetadataNotFound ErrorCodeT = 1

	// ErrorCodeUserIDInvalid is returned when a user ID is changed
	// between versions of a record.
	ErrorCodeUserIDInvalid ErrorCodeT = 2

	// ErrorCodePublicKeyInvalid is returned when a public key used
	// in a signature is not valid.
	ErrorCodePublicKeyInvalid ErrorCodeT = 3

	// ErrorCodeSignatureInvalid is returned when the signature does
	// not match the expected signature.
	ErrorCodeSignatureInvalid ErrorCodeT = 4

	// ErrorCodeStatusChangeMetadataNotFound is returned when a record
	// is having its status updated but is missing the status change
	// metadata.
	ErrorCodeStatusChangeMetadataNotFound ErrorCodeT = 5

	// ErrorCodeTokenInvalid is returned when a token that is included
	// in the metadata does not match the token of the record that the
	// command is being executed on.
	ErrorCodeTokenInvalid ErrorCodeT = 6

	// ErrorCodeStatusInvalid is returned when the status defined in
	// the status change metadata does not match the record status.
	ErrorCodeStatusInvalid ErrorCodeT = 7

	// ErrorCodeReasonMissing is returned when the status change reason
	// is required but is not included.
	ErrorCodeReasonMissing ErrorCodeT = 8

	// ErrorCodeLast unit test only.
	ErrorCodeLast ErrorCodeT = 9
)

var (
	// ErrorCodes contains the human readable errors.
	ErrorCodes = map[ErrorCodeT]string{
		ErrorCodeInvalid:                      "error code invalid",
		ErrorCodeUserMetadataNotFound:         "user metadata not found",
		ErrorCodeUserIDInvalid:                "user id invalid",
		ErrorCodePublicKeyInvalid:             "public key invalid",
		ErrorCodeSignatureInvalid:             "signature invalid",
		ErrorCodeStatusChangeMetadataNotFound: "status change metadata not found",
		ErrorCodeTokenInvalid:                 "token invalid",
		ErrorCodeStatusInvalid:                "status invalid",
		ErrorCodeReasonMissing:                "status change reason is missing",
	}
)

// UserMetadata contains user metadata about a politeiad record. It is
// generated by the server and saved to politeiad as a metadata stream.
//
// Signature is the client signature of the hex encoded record merkle root. The
// merkle root is the ordered merkle root of all user submitted politeiad
// files. The merkle root is hex encoded before being signed so that the
// signature is consistent with how politeiad signs the merkle root.
type UserMetadata struct {
	UserID    string `json:"userid"`    // Author user ID
	PublicKey string `json:"publickey"` // Key used for signature
	Signature string `json:"signature"` // Signature of merkle root
}

// StatusChangeMetadata contains the user signature for a record status change.
//
// Signature is the client signature of the Token+Version+Status+Reason.
type StatusChangeMetadata struct {
	Token     string `json:"token"`
	Version   uint32 `json:"version"`
	Status    uint32 `json:"status"`
	Reason    string `json:"reason,omitempty"`
	PublicKey string `json:"publickey"`
	Signature string `json:"signature"`
	Timestamp int64  `json:"timestamp"`
}

// Author returns the user ID of a record's author.
type Author struct{}

// AuthorReply is the reply to the Author command.
type AuthorReply struct {
	UserID string `json:"userid"`
}

// UserRecords retrieves the tokens of all records that were submitted by the
// provided user ID. The returned tokens are sorted from newest to oldest.
type UserRecords struct {
	UserID string `json:"userid"`
}

// UserRecordsReply is the reply to the UserInv command.
type UserRecordsReply struct {
	Unvetted []string `json:"unvetted"`
	Vetted   []string `json:"vetted"`
}
