// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package app

import (
	"context"
)

// App provides an API for accessing the plugin configuration of a politeia
// app. An app is essentially just a unique configuration of plugins.
type App interface {
	// TODO this needs to return reads and writes differently so that the
	// server can validate them appropriately.
	// Cmds returns the plugin commands that are part of the app.
	Cmds() []CmdDetails

	// PreventBatchedReads returns a list of plugin commands that are not
	// allowed to be included in a read batch.
	//
	// Prior to executing a read batch, the politeia server will verify that the
	// read commands are allowed to be executed as part of a read batch. This
	// allows the app prevent expensive reads from being batched. By default, all
	// read commands are allowed to be batched.
	PreventBatchedReads() []CmdDetails

	// Write executes a plugin write command.
	//
	// Any updates made to the session will be persisted by the politeia server.
	Write(context.Context, *Session, Cmd) (*CmdReply, error)

	// Read executes a read-only plugin command.
	Read(context.Context, Session, Cmd) (*CmdReply, error)

	// ReadBatch executes a batch of read-only plugin command.
	// ReadBatch(context.Context, Session, []Cmd) ([]CmdReply, error)
}
