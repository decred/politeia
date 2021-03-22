// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package usermd provides a politeiad plugin that extends records with user
// metadata and provides an API for retrieving records by user metadata.
package usermd

const (
	// PluginID is the unique identifier for this plugin.
	PluginID = "usermd"

	// Plugin commands
	CmdAuthor      = "author"      // Get record author
	CmdUserRecords = "userrecords" // Get user submitted records

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
	// User error codes
	ErrorCodeInvalid                      ErrorCodeT = 0
	ErrorCodeUserMetadataNotFound         ErrorCodeT = 1
	ErrorCodeUserIDInvalid                ErrorCodeT = 2
	ErrorCodePublicKeyInvalid             ErrorCodeT = 3
	ErrorCodeSignatureInvalid             ErrorCodeT = 4
	ErrorCodeStatusChangeMetadataNotFound ErrorCodeT = 5
	ErrorCodeTokenInvalid                 ErrorCodeT = 6
	ErrorCodeStatusInvalid                ErrorCodeT = 7
	ErrorCodeReasonInvalid                ErrorCodeT = 8
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
		ErrorCodeReasonInvalid:                "status reason invalid",
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
	Reason    string `json:"message,omitempty"`
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
