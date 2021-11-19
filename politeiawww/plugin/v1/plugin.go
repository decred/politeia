// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

import (
	"database/sql"
	"fmt"
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

	// SetPermission sets the user permission level for a command.
	SetPermission(cmd, permissionLevel string)

	// Permissions returns the user permissions for each plugin commands. These
	// are provided to the AuthPlugin on startup. The AuthPlugin handles user
	// authorization at runtime.
	Permissions() map[string]string // [cmd]permissionLevel

	// Hook executes a plugin hook.
	Hook(HookArgs) error

	// HookTx executes a plugin hook using a database transaction.
	HookTx(*sql.Tx, HookArgs) error

	// WriteTx executes a write plugin command using a database transaction.
	WriteTx(*sql.Tx, WriteArgs) (*Reply, error)

	// Read executes a read plugin command.
	Read(ReadArgs) (*Reply, error)

	// ReadTx executes a read plugin command using a database transaction.
	ReadTx(*sql.Tx, ReadArgs) (*Reply, error)
}

// HookArgs contains the arguments for the plugin hook methods.
type HookArgs struct {
	Type  HookT
	Cmd   Cmd
	Reply *Reply
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

// Reply is the reply to a plugin command.
type Reply struct {
	Payload string // JSON encoded
	Error   error
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

// UserError is the reply that is returned when a plugin command encounters an
// error that was caused by the user.
type UserError struct {
	PluginID     string `json:"pluginid"`
	ErrorCode    uint32 `json:"errorcode"`
	ErrorContext string `json:"errorcontext,omitempty"`
}

// Error satisfies the error interface.
func (e UserError) Error() string {
	return fmt.Sprintf("%v plugin user error: %v", e.PluginID, e.ErrorCode)
}
