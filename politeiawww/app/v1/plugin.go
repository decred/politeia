// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

import (
	"database/sql"
)

// Plugin represents an app plugin.
type Plugin interface {
	// ID returns the plugin ID.
	ID() string

	// Version returns the lowest supported plugin API version.
	Version() uint32

	// UpdateSettings updates plugin setting values.
	UpdateSettings([]Setting) error

	// Cmds returns all registered plugin commands.
	Cmds() []CmdDetails

	// NewUserCmds returns all of the plugin commands that should result in a new
	// user being inserted into the user database.
	//
	// Plugins do not have direct access to the user database, so they are not
	// able to insert new user records. The app handles this operation.
	//
	// Plugin write command that have been included in this list will be executed
	// differently. Prior to the execution of the command, the app will create a
	// new user record in the user database. The newly created user is passed to
	// the plugin as a write command argument, just like during the execution of
	// a standard write command. The database transaction that was used to create
	// the user record will only be committed if the plugin command executes
	// without any errors.
	NewUserCmds() []CmdDetails

	// TxWrite executes a write plugin command using a database transaction.
	TxWrite(*sql.Tx, WriteArgs) (*CmdReply, error)

	// TxRead executes a read plugin command using a database transaction.
	TxRead(*sql.Tx, ReadArgs) (*CmdReply, error)

	// TxHook executes a plugin hook using a database transaction.
	TxHook(*sql.Tx, HookArgs) error

	// Read executes a non-atomic read plugin command.
	Read(ReadArgs) (*CmdReply, error)
}

// Setting represents a configurable plugin setting.
//
// The value can either contain a single value or multiple values. Multiple
// values will be formatted as a JSON encoded []string.
type Setting struct {
	Name  string
	Value string
}

// CmdDetails contains the details for a registered plugin command.
type CmdDetails struct {
	Version uint32 // Plugin API version
	Name    string // Command name
}

// WriteArgs contain the arguments for the plugin write methods.
//
// Updates that are made to the User object during write command execution are
// persisted by the app on successful completion of the command.
type WriteArgs struct {
	Cmd  Cmd
	User *User
}

// ReadArgs contain the arguments for the plugin read methods.
//
// Updates that are made to the User object during read command execution are
// ignored.
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
	Name     string
	Payload  string // JSON encoded
}

// CmdReply is the reply to a plugin command.
type CmdReply struct {
	Payload string // JSON encoded
}
