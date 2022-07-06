// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v3

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
	// This route accepts a Cmd and returns a CmdReply.
	NewUserRoute = "/newuser"

	// WriteRoute is a POST request route that executes a plugin command that
	// writes data to the backend.
	//
	// This route is CSRF protected. Clients must obtain CSRF tokens from the
	// Version route before they'll be able to use this route. A 403 is returned
	// if the client attempts to use this route without the proper CSRF tokens.
	//
	// This route accepts a Cmd and returns a CmdReply.
	WriteRoute = "/write"

	// ReadRoute is a POST request route that executes an individual read-only
	// plugin command. This route is intended to be used for expensive plugin
	// read commands that cannot be batched due to their memory or performance
	// requirements. This allows the sysadmin to set different rate limiting
	// constraints for expensive commands.
	//
	// This route accepts a Cmd and returns a CmdReply.
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
