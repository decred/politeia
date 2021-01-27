// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package user provides a politeiad plugin that extends records with user
// metadata and provides an API for retrieving records by user metadata.
package user

const (
	PluginID = "user"

	// Plugin commands
	CmdAuthor      = "author"      // Get record author
	CmdUserRecords = "userrecords" // Get user submitted records

	// TODO add record status change mdstream
	// TODO make whether user md is required a plugin setting

	// TODO MDStream IDs need to be plugin specific. If we can't then
	// we need to make a mdstream package to aggregate all the mdstream
	// ID.

	// MDStreamIDUserMetadata is the politeiad metadata stream ID for
	// the UserMetadata structure.
	MDStreamIDUserMetadata = 1
)

// ErrorCodeT represents a plugin error that was caused by the user.
type ErrorCodeT int

const (
	// TODO number
	// User error codes
	ErrorCodeInvalid ErrorCodeT = iota
	ErrorCodeUserMetadataNotFound
	ErrorCodeUserIDInvalid
	ErrorCodePublicKeyInvalid
	ErrorCodeSignatureInvalid
	ErrorCodeUpdateNotAllowed
)

var (
	// TODO fill in
	// ErrorCodes contains the human readable errors.
	ErrorCodes = map[ErrorCodeT]string{
		ErrorCodeInvalid: "error code invalid",
	}

	/*
		// statusReasonRequired contains the list of proposal statuses that
		// require an accompanying reason to be given for the status change.
		statusReasonRequired = map[piv1.PropStatusT]struct{}{
			piv1.PropStatusCensored:  {},
			piv1.PropStatusAbandoned: {},
		}
	*/
)

// UserMetadata contains user metadata about a politeiad record. It is
// generated by the server and saved to politeiad as a metadata stream.
//
// Signature is the client signature of the record merkle root. The merkle root
// is the ordered merkle root of all user submitted politeiad files.
type UserMetadata struct {
	UserID    string `json:"userid"`    // Author user ID
	PublicKey string `json:"publickey"` // Key used for signature
	Signature string `json:"signature"` // Signature of merkle root
}

// Author returns the user ID of a record's author. If no UserMetadata is
// present for the record then an empty string will be returned.
type Author struct{}

// AuthorReply is the reply to the Author command.
type AuthorReply struct {
	UserID string `json:"userid"`
}

// UserRecords retrieves the tokens of all records that were
// submitted by the provided user ID. The returned tokens are sorted from
// newest to oldest.
type UserRecords struct {
	UserID string `json:"userid"`
}

// UserRecordsReply is the reply to the UserInv command.
type UserRecordsReply struct {
	Records []string `json:"records"`
}
