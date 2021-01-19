// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

import "fmt"

const (
	// APIRoute is prefixed onto all routes defined in this package.
	APIRoute = "/records/v1"

	// Record routes
	RouteTimestamps = "/timestamps"
)

// ErrorCodeT represents a user error code.
type ErrorCodeT int

const (
	// Error codes
	ErrorCodeInvalid            ErrorCodeT = 0
	ErrorCodeInputInvalid       ErrorCodeT = 1
	ErrorCodeRecordNotFound     ErrorCodeT = 2
	ErrorCodeRecordStateInvalid ErrorCodeT = 3
)

var (
	// ErrorCodes contains the human readable errors.
	ErrorCodes = map[ErrorCodeT]string{
		ErrorCodeInvalid:            "error invalid",
		ErrorCodeInputInvalid:       "input invalid",
		ErrorCodeRecordNotFound:     "record not found",
		ErrorCodeRecordStateInvalid: "record state invalid",
	}
)

// UserErrorReply is the reply that the server returns when it encounters an
// error that is caused by something that the user did (malformed input, bad
// timing, etc). The HTTP status code will be 400.
type UserErrorReply struct {
	ErrorCode    ErrorCodeT `json:"errorcode"`
	ErrorContext string     `json:"errorcontext"`
}

// Error satisfies the error interface.
func (e UserErrorReply) Error() string {
	return fmt.Sprintf("user error code: %v", e.ErrorCode)
}

// PluginErrorReply is the reply that the server returns when it encounters
// a plugin error.
type PluginErrorReply struct {
	PluginID     string `json:"pluginid"`
	ErrorCode    int    `json:"errorcode"`
	ErrorContext string `json:"errorcontext"`
}

// Error satisfies the error interface.
func (e PluginErrorReply) Error() string {
	return fmt.Sprintf("plugin user error code: %v", e.ErrorCode)
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

// StateT represents a record state.
type StateT int

const (
	// StateInvalid indicates an invalid record state.
	StateInvalid StateT = 0

	// StateUnvetted indicates a record has not been made public yet.
	StateUnvetted StateT = 1

	// StateVetted indicates a record has been made public.
	StateVetted StateT = 2
)

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

// Timestamp contains all of the data required to verify that a piece of record
// data was timestamped onto the decred blockchain.
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

// Timestamps requests the timestamps for a specific record version. If the
// version is omitted, the timestamps for the most recent version will be
// returned.
type Timestamps struct {
	State   StateT `json:"state"`
	Token   string `json:"token"`
	Version string `json:"version,omitempty"`
}

// TimestampsReply is the reply to the Timestamps command.
type TimestampsReply struct {
	RecordMetadata Timestamp `json:"recordmetadata"`

	// map[metadataID]Timestamp
	Metadata map[uint64]Timestamp `json:"metadata"`

	// map[filename]Timestamp
	Files map[string]Timestamp `json:"files"`
}
