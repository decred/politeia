// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v3

import "fmt"

const (
	// APIVersion is the version of the API that this package represents.
	APIVersion uint32 = 3

	// APIVersionPrefix is prefixed onto all routes defined in this package.
	APIVersionPrefix = "/v3"

	// VersionRoute is a GET request route that returns the server version
	// information and sets the CSRF tokens for the client. The VersionReply can
	// be retrieved from both the "/" route and the "/v3/version" route. This
	// allows clients to be able to determine version information without needing
	// to have any prior knowledge of the API.
	//
	// This route sets CSRF tokens for clients using the double submit cookie
	// technique. A token is set in a cookie and a token is set in a header.
	// Clients MUST make a successful Version call before they'll be able to
	// use CSRF protected routes.
	//
	// This route returns a VersionReply.
	VersionRoute = "/version"

	// PolicyRoute is a GET request route that returns the API policy
	// information.
	//
	// This route returns a PolicyReply.
	PolicyRoute = "/policy"

	// NewUserRoute is a POST request route that executes a plugin command that
	// creates a new user. This is the only route that can be used for plugin
	// commands that result in a new user being created.
	//
	// This route is CSRF protected. Clients must obtain CSRF tokens from the
	// Version route before they'll be able to use this route. A 403 is returned
	// if the client attempts to use this route without the proper CSRF tokens.
	//
	// This route accepts a PluginCmd and returns a PluginReply.
	NewUserRoute = "/newuser"

	// WriteRoute is a POST request route that executes a plugin command that
	// writes data to the backend.
	//
	// This route is CSRF protected. Clients must obtain CSRF tokens from the
	// Version route before they'll be able to use this route. A 403 is returned
	// if the client attempts to use this route without the proper CSRF tokens.
	//
	// This route accepts a PluginCmd and returns a PluginReply.
	WriteRoute = "/write"

	// ReadRoute is a POST request route that executes an individual read-only
	// plugin command. This route is intended to be used for expensive plugin
	// read commands that cannot be batched due to their memory or performance
	// requirements. This allows the sysadmin to set different rate limiting
	// constraints for expensive commands.
	//
	// This route accepts a PluginCmd and returns a PluginReply.
	ReadRoute = "/read"

	// ReadBatchRoute is a POST request route that executes a batch of read-only
	// plugin commands. This route is intended to be used for inexpensive plugin
	// commands that will not cause performance issues during the execution of
	// large batches.
	//
	// This route accepts a Batch and returns a BatchReply.
	ReadBatchRoute = "/readbatch"
)

const (
	// CSRFTokenHeader is the header that will contain a CSRF token.
	CSRFTokenHeader = "X-CSRF-Token"

	// SessionCookieName is the cookie name for the session cookie. Clients will
	// have the session cookie set the first time a plugin command route is hit.
	SessionCookieName = "session"
)

// Version contains the GET request parameters for the VersionRoute. The
// VersionRoute returns a VersionReply.
//
// This route sets CSRF tokens for clients using the double submit cookie
// technique. A token is set in a cookie and a token is set in a header.
// Clients MUST make a successful Version call before they'll be able to
// use CSRF protected routes.
type Version struct{}

// VersionReply is the reply for the VersionRoute. It contains the server
// version information and the list of plugins that the server is running. The
// client should verify compatibility with the server version and plugins.
type VersionReply struct {
	// APIVersion is the lowest supported API version.
	APIVersion uint32 `json:"apiversion"`

	// BuildVersion is the sematic version of the server build.
	BuildVersion string `json:"buildversion"`

	// Plugins contains the plugin ID and lowest supported plugin API version
	// for all registered plugins.
	Plugins map[string]uint32 `json:"plugins"` // [pluginID]version
}

// Policy contains the GET request parameters for the PolicyRoute. The
// PolicyRoute returns a PolicyReply.
type Policy struct{}

// PolicyReply is the reply for the PolicyRoute. It contains API policy
// information.
type PolicyReply struct {
	// ReadBatchLimit contains the maximum number of plugin commands allowed in
	// a read batch request.
	ReadBatchLimit uint32 `json:"readbatchlimit"`
}

// Cmd represents a plugin command.
type Cmd struct {
	PluginID string `json:"pluginid"`
	Version  uint32 `json:"version"` // Plugin API version
	Cmd      string `json:"cmd"`
	Payload  string `json:"payload"` // Cmd payload, JSON encoded
}

// CmdReply is the reply to a Cmd request.
type CmdReply struct {
	PluginID string `json:"pluginid"`
	Version  uint32 `json:"version"` // Plugin API version
	Cmd      string `json:"cmd"`
	Payload  string `json:"payload"` // Reply payload, JSON encoded
	Error    error  `json:"error,omitempty"`
}

// Batch contains a batch of read-only plugin commands.
type Batch struct {
	Cmds []Cmd `json:"cmds"`
}

// BatchReply is the reply to a Batch request.
type BatchReply struct {
	Replies []CmdReply `json:"replies"`
}

// PluginError is returned when a plugin command encounters an error that was
// caused by the user (ex. malformed input, bad timing, etc). The HTTP status
// code will be 200 and the error will be returned in the Error field of the
// PluginReply.
type PluginError struct {
	PluginID     string `json:"pluginid"`
	ErrorCode    uint32 `json:"errorcode"`
	ErrorContext string `json:"errorcontext,omitempty"`
}

// Error satisfies the error interface.
func (e PluginError) Error() string {
	return fmt.Sprintf("%v plugin error code: %v", e.PluginID, e.ErrorCode)
}

// UserError is returned in the response body when the server encounters an
// error that is caused by something that the user did, such as a invalid
// request body, and the error occurred prior to execution of the plugin
// command. The HTTP status code will be 400.
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

	// ErrorCodePluginNotAuthorized is returned when a plugin is attempting to
	// execute a command using a route that it is not authorized to use.
	ErrorCodePluginNotAuthorized ErrorCodeT = 3

	// ErrorCodeBatchLimitExceeded is return when the number of plugin commands
	// that are allowed to be executed in a batch request is exceeded.
	ErrorCodeBatchLimitExceeded ErrorCodeT = 4
)

var (
	// ErrorCodes contains the human readable errors.
	ErrorCodes = map[ErrorCodeT]string{
		ErrorCodeInvalid:             "invalid error",
		ErrorCodeInvalidInput:        "invalid input",
		ErrorCodePluginNotFound:      "plugin not found",
		ErrorCodePluginNotAuthorized: "plugin not authorized",
		ErrorCodeBatchLimitExceeded:  "batch limit exceeded",
	}
)

// InternalError is returned in the response body when the server encounters an
// unrecoverable error. The ErrorCode field will contain a Unix timestamp that
// the user can provide to the server operator to track down the error details
// in the logs. The HTTP status code will be 500.
type InternalError struct {
	ErrorCode int64 `json:"errorcode"`
}

// Error satisfies the error interface.
func (e InternalError) Error() string {
	return fmt.Sprintf("internal server error: %v", e.ErrorCode)
}
