// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

import (
	"database/sql"
	"fmt"

	"github.com/google/uuid"
)

// Plugin represents a politeia plugin.
//
// Updates to the plugin data in the User object will only be persisted by the
// caller for operations that are part of a write command. Updates made during
// read commands are ignored.
type Plugin interface {
	// ID returns the plugin ID.
	ID() string

	// Version returns the lowest supported plugin API version.
	Version() uint32

	// Permissions returns the user permissions for each plugin commands. These
	// are provided to the AuthPlugin on startup. The AuthPlugin handles user
	// authorization at runtime.
	Permissions() map[string]string // [cmd]permissionLevel

	// Hook executes a plugin hook.
	Hook(HookT, Cmd, *User) error

	// HookTx executes a plugin hook using a database transaction.
	HookTx(*sql.Tx, HookT, Cmd, *User) error

	// WriteTx executes a write plugin command using a database transaction.
	WriteTx(*sql.Tx, Cmd, *User) (*Reply, error)

	// Read executes a read plugin command.
	Read(Cmd, *User) (*Reply, error)

	// ReadTx executes a read plugin command using a database transaction.
	ReadTx(*sql.Tx, Cmd, *User) (*Reply, error)
}

// Authorizer provides user authorization for plugin commands.
//
// Changes made to the Session and User will be persisted by the caller.
type Authorizer interface {
	Authorize(s *Session, u *User, pluginID, cmd string) error
}

type Cmd struct {
	Cmd     string
	Payload string // JSON encoded
}

type Reply struct {
	Payload string // JSON encoded
	Error   error
}

type User struct {
	ID         uuid.UUID // Unique ID
	PluginData *PluginData
}

// PluginData contains the data that is owned by the plugin.
//
// These fields can be updated by the plugin during execution of a write
// command. The PluginData methods MUST be used if the plugin wants the changes
// persisted. Updates made using the PluginData methods will be persisted by
// the caller. Any updates made during the execution of a read-only command
// will be ignored.
//
// The encrypted data blob will be provided to the plugin as clear text, but
// will be saved to the database by the caller as encrypted. The plugin does
// not need to worry about encrypting/decrypting the data.
type PluginData struct {
	clearText []byte
	encrypted []byte
	updated   bool
}

func NewPluginData(clearText, encrypted []byte) *PluginData {
	return &PluginData{
		clearText: clearText,
		encrypted: encrypted,
	}
}

func (d *PluginData) ClearText() []byte {
	return d.clearText
}

func (d *PluginData) SetClearText(b []byte) {
	d.clearText = b
	d.updated = true
}

func (d *PluginData) Encrypted() []byte {
	return d.encrypted
}

func (d *PluginData) SetEncrypted(b []byte) {
	d.encrypted = b
	d.updated = true
}

func (d *PluginData) Updated() bool {
	return d.updated
}

type Session struct {
	UserID    string
	CreatedAt int64
	Delete    bool
}

type HookT string

const (
	HookInvalid   HookT = "invalid"
	HookPreWrite  HookT = "pre-write"
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
