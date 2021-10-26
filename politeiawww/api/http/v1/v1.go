// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

import "fmt"

const (
	// APIVersion if the version of the API that this package represents.
	APIVersion uint32 = 1

	// APIRoute is prefixed onto all routes defined in this package.
	APIRoute = "/v1"

	// RouteVersion is a GET request route that returns the server version
	// information and sets CSRF tokens for the client. The VersionReply can be
	// retrieved from both the "/" route and the "/v1/version" route. This allows
	// clients to be able to determine version information without needing to
	// have any prior knowledge of the API.
	//
	// This route sets CSRF tokens for clients using the double submit cookie
	// technique. A token is set in a cookie and a token is set in a header.
	// Clients MUST make a successful Version call before they'll be able to
	// use CSRF protected routes.
	RouteVersion = "/version"

	// RouteWrite is a POST request route that executes a plugin write command.
	//
	// This route is CSRF protected. Clients must obtain CSRF tokens from the
	// Version route before they'll be able to use this route. A 403 is returned
	// if the client attempts to use this route without the proper CSRF tokens.
	RouteWrite = "/write"

	// RouteRead is a POST request route that executes an individual plugin read
	// command. This route is intended to be used for expensive plugin read
	// commands that should not be batched due to their memory or performance
	// requirements. This allows the sysadmin to set different rate limiting
	// constrains for these expensive commands.
	RouteRead = "/read"

	// RouteReadBatch is a POST request route that executes a batch of plugin
	// read commands. This route is intended to be used for inexpensive plugin
	// commands that will not cause performance issues during the execution of
	// large batches.
	RouteReadBatch = "/readbatch"
)

const (
	// CSRFTokenHeader is the header that will contain a CSRF token.
	CSRFTokenHeader = "X-CSRF-Token"

	// SessionCookieName is the cookie name for the session cookie. A client will
	// have the session cookie set the first time one of the read or write routes
	// is hit.
	SessionCookieName = "session"
)

// Version returns the server version information and the list of plugins that
// the server is running. The client should verify compatibility with the
// server version and plugins.
//
// This also sets sets CSRF tokens for clients using the double submit cookie
// technique. A token is set in a cookie and a token is set in a header.
// Clients MUST make a successful Version call before they'll be able to use
// CSRF protected routes.
type Version struct{}

// VersionReply is the reply to the Version command.
type VersionReply struct {
	// APIVersion is the lowest supported API version.
	APIVersion uint32 `json:"apiversion"`

	// BuildVersion is the sematic version of the server build.
	BuildVersion string `json:"buildversion"`

	// Plugins contains the plugin IDs of the server plugins.
	Plugins []string `json:"plugins"`
}

type PluginCmd struct {
	PluginID string `json:"pluginid"`
	Cmd      string `json:"cmd"`
	Payload  string `json:"payload"` // Cmd payload, JSON encoded
}

type PluginReply struct {
	PluginID string `json:"pluginid"`
	Cmd      string `json:"cmd"`
	Payload  string `json:"payload"` // Reply payload, JSON encoded
	Error    error  `json:"error,omitempty"`
}

type ReadBatch struct {
	Cmds []PluginCmd `json:"cmds"`
}

type ReadBatchReply struct {
	Replies []PluginReply `json:"replies"`
}

// PluginError is the reply that is returned when a plugin command encounters
// an error that was caused by the user (ex. malformed input, bad timing, etc).
// The HTTP status code will be 200 and the error will be returned in the
// Error field of the JSON encoded response body.
type PluginError struct {
	PluginID     string `json:"pluginid"`
	ErrorCode    uint32 `json:"errorcode"`
	ErrorContext string `json:"errorcontext,omitempty"`
}

// Error satisfies the error interface.
func (e PluginError) Error() string {
	return fmt.Sprintf("%v plugin error code: %v", e.PluginID, e.ErrorCode)
}

// ErrorCodeT represents a user error code.
type ErrorCodeT uint32

const (
	// ErrorCodeInvalid is an invalid error code.
	ErrorCodeInvalid ErrorCodeT = 0

	// ErrorCodeInvalidInput is returned when the request body could not be
	// parsed.
	ErrorCodeInvalidInput ErrorCodeT = 1

	// ErrorCodePluginNotFound is returned when a plugin ID is provided that
	// does not correspond to a registered plugin.
	ErrorCodePluginNotFound ErrorCodeT = 2
)

var (
	// ErrorCodes contains the human readable errors.
	ErrorCodes = map[ErrorCodeT]string{
		ErrorCodeInvalid:        "invalid error",
		ErrorCodeInvalidInput:   "invalid input",
		ErrorCodePluginNotFound: "plugin not found",
	}
)

// TODO these should be returned in the PluginReply too.
//
// UserError is the reply that the server returns when it encounters an error
// prior to plugin command execution and that is caused by something that the
// user did, such as a invalid request body. The HTTP status code will be 400.
type UserError struct {
	ErrorCode    ErrorCodeT `json:"errorcode"`
	ErrorContext string     `json:"errorcontext,omitempty"`
}

// Error satisfies the error interface.
func (e UserError) Error() string {
	if e.ErrorContext == "" {
		return fmt.Sprintf("user error (%v): %v",
			e.ErrorCode, ErrorCodes[e.ErrorCode])
	}
	return fmt.Sprintf("user error (%v): %v, %v",
		e.ErrorCode, ErrorCodes[e.ErrorCode], e.ErrorContext)
}

// InternalError is the reply that the server returns when it encounters an
// unrecoverable error while executing a command. The HTTP status code will be
// 500 and the InternalError will be returned in the response body. The
// ErrorCode field will contain a Unix timestamp that the user can provide to
// the server operator to track down the error details in the logs.
type InternalError struct {
	ErrorCode int64 `json:"errorcode"`
}

// Error satisfies the error interface.
func (e InternalError) Error() string {
	return fmt.Sprintf("internal server error: %v", e.ErrorCode)
}
