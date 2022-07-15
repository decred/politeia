// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v3

// UserError represents an error that occurs prior to the execution of any
// plugin commands and that was caused by the user.
//
// The server will reply with a 400 HTTP status code and will return the JSON
// encoded UserError in the response body.
type UserError struct {
	ErrorCode    ErrCode `json:"errorcode"`
	ErrorContext string  `json:"errorcontext,omitempty"`
}

// ErrCode represents a user error code.
type ErrCode uint32

const (
	// ErrCodeInvalid is an invalid error code.
	ErrCodeInvalid ErrCode = 0

	// ErrCodeInvalidInput is returned when the request body could not be parsed.
	ErrCodeInvalidInput ErrCode = 1

	// ErrCodePluginCmdNotFound is returned when a plugin command is provided
	// that does not correspond to a registered plugin command.
	ErrCodeInvalidPluginCmd ErrCode = 2

	// ErrCodeBatchLimitExceeded is return when the number of plugin commands
	// that are allowed to be executed in a batch request is exceeded.
	ErrCodeBatchLimitExceeded ErrCode = 3

	// ErrCodeBatchedReadNotAllowed is returned when a plugin command has been
	// included in a read batch that is not allowed to be executed as a batched
	// command. This is usually because the command is expensive and must be
	// executed individually.
	ErrCodeBatchedReadNotAllowed ErrCode = 4
)

var (
	// ErrCodes contains the human readable errors.
	ErrCodes = map[ErrCode]string{
		ErrCodeInvalid:               "invalid error",
		ErrCodeInvalidInput:          "invalid input",
		ErrCodeInvalidPluginCmd:      "invalid plugin command",
		ErrCodeBatchLimitExceeded:    "batch limit exceeded",
		ErrCodeBatchedReadNotAllowed: "batched read is not allowed",
	}
)

// InternalError represents an internal server error.
//
// The server will reply with a 500 HTTP status code and will return the JSON
// encoded InternalError in the response body.
//
// The ErrorCode field will contain a Unix timestamp that the user can provide
// to the server operator to track down the error details in the logs.
type InternalError struct {
	ErrorCode int64 `json:"errorcode"`
}
