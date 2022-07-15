// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v3

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
	Name     string `json:"name"`
	Payload  string `json:"payload"` // JSON encoded
}

// CmdReply is the reply to a Cmd request.
type CmdReply struct {
	PluginID string       `json:"pluginid"`
	Version  uint32       `json:"version"` // Plugin API version
	Name     string       `json:"name"`
	Payload  string       `json:"payload"` // JSON encoded
	Error    *PluginError `json:"error,omitempty"`
}

// PluginError represents an error that occurred during the execution of a
// plugin command and that was caused by the user (ex. bad command input).
//
// A PluginError is returned in the CmdReply.
type PluginError struct {
	ErrorCode    uint32 `json:"errorcode"`
	ErrorContext string `json:"errorcontext,omitempty"`
}

// Batch contains a batch of read-only plugin commands.
type Batch struct {
	Cmds []Cmd `json:"cmds"`
}

// BatchReply is the reply to a Batch request.
type BatchReply struct {
	Replies []CmdReply `json:"replies"`
}
