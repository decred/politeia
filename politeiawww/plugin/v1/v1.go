// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

import (
	"database/sql"
	"fmt"

	"github.com/decred/politeia/politeiawww/user"
	"github.com/google/uuid"
)

// NOTE: this plugin API is not stable and may be subject to breaking changes.

// Plugin represents a politeia user plugin.
//
// Plugins are allowed to update the session values. Updated values will be
// persisted by the caller.
//
// Updates to the user object plugin data during Write method execution will be
// persisted by the caller. Updates made during any other method are ignored.
type Plugin interface {
	// Hook executes a plugin hook.
	Hook(h HookT, cmd Cmd, s *Session, usr *user.User) error

	// Read executes a read plugin command.
	Read(cmd Cmd, s *Session, usr *user.User) (*Reply, error)

	// TxHook executes a plugin hook using a database transaction.
	TxHook(tx *sql.Tx, h HookT, cmd Cmd, s *Session, usr *user.User) error

	// TxWrite executes a write plugin command using a database transaction.
	TxWrite(tx *sql.Tx, cmd Cmd, s *Session, usr *user.User) (*Reply, error)

	// TxRead executes a read plugin command using a database transaction.
	TxRead(tx *sql.Tx, cmd Cmd, s *Session, usr *user.User) (*Reply, error)
}

type Cmd struct {
	Cmd     string
	Payload string // JSON encoded
}

type Reply struct {
	Payload string // JSON encoded
	Error   error
}

type Session struct {
	Values  map[string]interface{}
	Updated bool
}

func (s *Session) SetValue(key string, value interface{}) {
	s.Values[key] = value
	s.Updated = true
}

type User struct {
	ID          uuid.UUID // Unique ID
	Deactivated bool
	PluginData  PluginData
}

// PluginData contains the data that is owned by the plugin. These fields can
// be updated by the plugin during execution of the plugin Write method using
// the SetClearText() and SetEncrypted() methods. Changes made using these
// methods will be persisted by the caller. Any updates made to these fields
// during execution of all other methods will be ignored.
//
// The encrypted data blob will be provided to the plugin as clear text, but
// will be saved to the database by the caller as encrypted. The plugin does
// not need to worry about encrypting/decrypting any data.
type PluginData struct {
	ClearText        []byte
	ClearTextUpdated bool
	Encrypted        []byte
	EncryptedUpdated bool
}

func (d *PluginData) SetClearText(b []byte) {
	d.ClearText = b
	d.ClearTextUpdated = true
}

func (d *PluginData) SetEncrypted(b []byte) {
	d.Encrypted = b
	d.EncryptedUpdated = true
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
	return fmt.Sprintf("plugin user error: %v", e.ErrorCode)
}
