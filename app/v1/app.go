// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

import "context"

// App provides an API for accessing the plugin configuration of a politeia
// app. An app is essentially just a unique configuration of plugins.
type App interface {
	// Plugins returns all of the plugins that are part of the app.
	Plugins() []Plugin

	// AuthManager returns the app's AuthManager.
	AuthManager() AuthManager

	// Cmds returns all of the plugin commands that are part of the app.
	Cmds() []CmdDetails

	// PreventBatchedReads returns a list of plugin commands that are not
	// allowed to be included in a read batch.
	//
	// Prior to executing a read batch, the politeia server will verify that the
	// read commands are allowed to be executed as part of a read batch. This
	// lets the app prevent expensive reads from being batched. By default, all
	// read commands are allowed to be batched.
	PreventBatchedReads() []CmdDetails

	// Write executes a plugin write command.
	Write(context.Context, Session, Cmd) (*CmdReply, error)

	// Read(context.Context, Session, Cmd) (*CmdReply, error)
	// ReadBatch(context.Context, Session, []Cmd) ([]CmdReply, error)
}
