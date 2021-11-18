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
// Updates to the User object plugin data will only be persisted by the caller
// for operations that are part of a write command. Updates made during read
// commands are ignored.
type Plugin interface {
	// ID returns the plugin ID.
	ID() string

	// Version returns the lowest supported plugin API version.
	Version() uint32

	// SetPermission sets the permission level for a command.
	SetPermission(cmd, permissionLevel string)

	// Permissions returns the user permissions for each plugin commands. These
	// are provided to the AuthPlugin on startup. The AuthPlugin handles user
	// authorization at runtime.
	Permissions() map[string]string // [cmd]permissionLevel

	// Hook executes a plugin hook.
	Hook(HookPayload) error

	// HookTx executes a plugin hook using a database transaction.
	HookTx(*sql.Tx, HookPayload) error

	// WriteTx executes a write plugin command using a database transaction.
	// TODO put these args in an struct
	WriteTx(*sql.Tx, Cmd, *User) (*Reply, error)

	// Read executes a read plugin command.
	// TODO put these args in an struct
	Read(Cmd, *User) (*Reply, error)

	// ReadTx executes a read plugin command using a database transaction.
	// TODO put these args in an struct
	ReadTx(*sql.Tx, Cmd, *User) (*Reply, error)
}

// UserManager provides methods that result in state changes to the user
// database that cannot be done inside of plugins.
//
// For example, plugins do not have access to the user database methods that
// insert or delete users from the database. These actions must be done by the
// caller. The UserManager interface allows plugins to add plugin specific
// behavior onto these actions.
//
// Any changes made to the User during method execution will be persisted by
// the caller.
type UserManager interface {
	// ID returns the plugin ID.
	ID() string

	// Version returns the lowest supported plugin API version.
	Version() uint32

	// NewUserCmd executes a command that results in a new user being added to
	// the database. The user provided to this method is a newly created user
	// that has not been inserted into the user database yet, but will be
	// inserted if this command executes successfully without any user errors
	// or unexpected errors.
	NewUserCmd(*sql.Tx, Cmd, *User) (*Reply, error)
}

// Authorizer provides user authorization for plugin commands.
//
// Any changes made to the Session or User during method execution will be
// persisted by the caller.
type Authorizer interface {
	// ID returns the plugin ID.
	ID() string

	// Version returns the lowest supported plugin API version.
	Version() uint32

	// Authorize checks if the user is authorized to execute a plugin command.
	//
	// A UserError is returned if the user is not authorized.
	Authorize(s *Session, u *User, pluginID string,
		version uint32, cmd string) error
}

type Cmd struct {
	PluginID string
	Version  uint32 // Plugin API version
	Cmd      string
	Payload  string // JSON encoded
}

type Reply struct {
	Payload string // JSON encoded
	Error   error
}

type HookPayload struct {
	Type  HookT
	Cmd   Cmd
	Reply *Reply
	User  *User
}

type HookT string

const (
	HookInvalid     HookT = "invalid"
	HookPreNewUser  HookT = "pre-new-user"
	HookPostNewUser HookT = "post-new-user"
	HookPreWrite    HookT = "pre-write"
	HookPostWrite   HookT = "post-write"
)

type Session struct {
	UserID    string
	CreatedAt int64
	Delete    bool
}

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
