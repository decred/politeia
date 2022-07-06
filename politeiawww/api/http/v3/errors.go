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

	// ErrCodePluginNotFound is returned when a plugin ID is provided that does
	// not correspond to a registered plugin.
	ErrCodePluginNotFound ErrCode = 2

	// ErrCodePluginNotAuthorized is returned when a plugin is attempting to
	// execute a command using a route that it is not authorized to use.
	ErrCodePluginNotAuthorized ErrCode = 3

	// ErrCodeBatchLimitExceeded is return when the number of plugin commands
	// that are allowed to be executed in a batch request is exceeded.
	ErrCodeBatchLimitExceeded ErrCode = 4
)

var (
	// ErrCodes contains the human readable errors.
	ErrCodes = map[ErrCode]string{
		ErrCodeInvalid:             "invalid error",
		ErrCodeInvalidInput:        "invalid input",
		ErrCodePluginNotFound:      "plugin not found",
		ErrCodePluginNotAuthorized: "plugin not authorized",
		ErrCodeBatchLimitExceeded:  "batch limit exceeded",
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
