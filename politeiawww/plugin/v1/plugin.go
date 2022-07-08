// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

import (
	"database/sql"
)

// Plugin represents a politeia plugin.
//
// Updates to the User object will be persisted by the backend for operations
// that are part of write commands. Updates made during read-only commands are
// ignored.
type Plugin interface {
	// ID returns the plugin ID.
	ID() string

	// Version returns the lowest supported plugin API version.
	Version() uint32

	// TxWrite executes a write plugin command using a database transaction.
	TxWrite(*sql.Tx, WriteArgs) (*CmdReply, error)

	// TxRead executes a read plugin command using a database transaction.
	TxRead(*sql.Tx, ReadArgs) (*CmdReply, error)

	// TxHook executes a plugin hook using a database transaction.
	TxHook(*sql.Tx, HookArgs) error

	// Read executes a non-atomic read plugin command.
	Read(ReadArgs) (*CmdReply, error)

	// IsNewUserCmd returns whether the provided command is a new user command,
	// meaning that the command will result in a new user being inserted in the
	// database.
	//
	// Plugins do not have direct access to the user database, so they are not
	// able to insert new user records. The backend handles this operation. Prior
	// to executing a plugin command, the backend uses this method to ask the
	// plugin if the command should result in a new user being inserted into the
	// database.
	//
	// When a plugin returns true, the backend will create a new user in the
	// database prior to executing the plugin command, pass the new user to the
	// plugin command for execution, then commit the sql transaction that was
	// used to insert the new user only if the plugin command executes without
	// any errors.
	// IsNewUserCmd(Cmd) bool
}

// WriteArgs contain the arguments for the plugin write methods.
type WriteArgs struct {
	Cmd  Cmd
	User *User
}

// ReadArgs contain the arguments for the plugin read methods.
type ReadArgs struct {
	Cmd  Cmd
	User *User
}

// HookArgs contains the arguments for the plugin hook methods.
type HookArgs struct {
	Type  Hook
	Cmd   Cmd
	Reply *CmdReply
	User  *User
}

// Cmd represents a plugin command.
type Cmd struct {
	PluginID string
	Version  uint32 // Plugin API version
	Cmd      string
	Payload  string // JSON encoded
}

// CmdReply is the reply to a plugin command.
type CmdReply struct {
	Payload string // JSON encoded
}
