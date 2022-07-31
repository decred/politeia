// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

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
	// BuildVersion is the sematic version of the app build.
	BuildVersion string `json:"buildversion"`

	// APIVersion is the lowest supported API version.
	APIVersion uint32 `json:"apiversion"`
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
	Plugin  string `json:"plugin"`
	Version uint32 `json:"version"` // Plugin API version
	Name    string `json:"name"`
	Payload string `json:"payload"` // JSON encoded
}

// CmdReply is the reply to a Cmd request.
type CmdReply struct {
	Plugin  string       `json:"plugin"`
	Version uint32       `json:"version"` // Plugin API version
	Name    string       `json:"name"`
	Payload string       `json:"payload"` // JSON encoded
	Error   *PluginError `json:"error,omitempty"`
}

// PluginError represents an error that occurred during the execution of a
// plugin command and that was caused by the user (ex. bad command input).
//
// A PluginError is returned in the CmdReply.
type PluginError struct {
	Code    uint32 `json:"code"`
	Context string `json:"context,omitempty"`
}

// Batch contains a batch of read-only plugin commands.
type Batch struct {
	Cmds []Cmd `json:"cmds"`
}

// BatchReply is the reply to a Batch request.
type BatchReply struct {
	Replies []CmdReply `json:"replies"`
}
