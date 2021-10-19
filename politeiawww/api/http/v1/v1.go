// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

const (
	// APIRoute is prefixed onto all routes defined in this package.
	APIRoute = "/v1"

	// RouteVersion returns server version information. The VersionReply is
	// returned from both the "/" route and the "/v1/version" route. This allows
	// clients to be able to determine version information without needing to
	// have any prior knowledge of the API.
	RouteVersion = "/version"

	// RouteWrite executes a plugin write command.
	RouteWrite = "/write"

	// RouteRead executes an individual plugin read command. This route is
	// intended to be used for expensive plugin read commands that should not
	// be batched due to their memory or performance requirements. This also
	// allows the sysadmin to set different rate limiting constrains for these
	// expensive commands.
	RouteRead = "/read"

	// RouteReads executes a batch of plugin read commands. This route is
	// intended to be used for inexpensive plugin commands that will not cause
	// performance issues during the execution of large batches.
	RouteReads = "/reads"
)

// Version returns the server version information and the list of plugins that
// the server is running. The client should verify compatibility with the
// server version and plugins.
type Version struct{}

// VersionReply is the reply to the Version command.
type VersionReply struct {
	// APIVersion is the lowest supported API version.
	APIVersion uint `json:"apiversion"`

	// APIRoute is the API route for the lowest supported API version.
	APIRoute string `json:"apiroute"`

	// BuildVersion is the sematic version of the server build.
	BuildVersion string `json:"buildversion"`

	// Plugins contains the plugin IDs of the running plugins.
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
}

// PluginError is the reply that is returned when a plugin command encounters
// an error that was caused by the user (ex. malformed input, bad timing, etc).
type PluginError struct {
	PluginID     string `json:"pluginid"`
	ErrorCode    uint32 `json:"errorcode"`
	ErrorContext string `json:"errorcontext,omitempty"`
}

type Write struct {
	PluginCmd PluginCmd `json:"plugincmd"`
}

type WriteReply struct {
	PluginReply PluginReply `json:"pluginreply"`
	Error       error       `json:"error,omitempty"`
}

// InternalErrorReply is the reply that the server returns when it encounters
// an unrecoverable error while executing a command. The HTTP status code will
// be 500 and the ErrorCode field will contain a Unix timestamp that the user
// can provide to the server operator to track down the error details in the
// logs.
type InternalError struct {
	ErrorCode int64 `json:"errorcode"`
}
