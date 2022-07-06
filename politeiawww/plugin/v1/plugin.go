// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

import (
	"database/sql"
)

// Plugin represents a politeia plugin.
//
// Updates to the User object plugin data will be persisted by the backend for
// operations that are part of write commands. Updates made during read-only
// commands are ignored.
type Plugin interface {
	// ID returns the plugin ID.
	ID() string

	// Version returns the lowest supported plugin API version.
	Version() uint32

	// Permissions returns the user permissions for each plugin commands. These
	// are provided to the AuthPlugin on startup. The AuthPlugin handles user
	// authorization at runtime.
	//
	// The permission levels are defined by the AuthPlugin and must be configured
	// for all commands. Failure to set the permission level for a command will
	// result in the plugin API routes returning a not authorized error when
	// attempting to execute the command.
	Permissions() map[string]string // [cmd]permissionLevel

	// Hook executes a plugin hook.
	Hook(HookArgs) error

	// Read executes a read plugin command.
	Read(ReadArgs) (*CmdReply, error)

	// TxHook executes a plugin hook using a database transaction.
	TxHook(*sql.Tx, HookArgs) error

	// TxWrite executes a write plugin command using a database transaction.
	TxWrite(*sql.Tx, WriteArgs) (*CmdReply, error)

	// TxRead executes a read plugin command using a database transaction.
	TxRead(*sql.Tx, ReadArgs) (*CmdReply, error)
}

// HookArgs contains the arguments for the plugin hook methods.
type HookArgs struct {
	Type  HookT
	Cmd   Cmd
	Reply *CmdReply
	User  *User
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

// HookT represents a plugin hook. Pre hooks allow plugins to add plugin
// specific validation onto external plugin commands. Post hooks allow plugins
// to update caches with any necessary changes that result from the execution
// of the command.
type HookT string

const (
	// HookInvalid is an invalid hook.
	HookInvalid HookT = "invalid"

	// HookPreNewUser is the hook that is executed before a NewUser command
	// is executed.
	HookPreNewUser HookT = "pre-new-user"

	// HookPostNewUser is the hook that is executed after the successful
	// execution of a NewUser command.
	HookPostNewUser HookT = "post-new-user"

	// HookPreWrite is the hook that is executed before a plugin write command
	// is executed.
	HookPreWrite HookT = "pre-write"

	// HookPostWrite is the hook that is executed after the successful execution
	// of a plugin write command.
	HookPostWrite HookT = "post-write"
)
