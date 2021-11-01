// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

import (
	"database/sql"
	"fmt"

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
	Hook(HookT, Cmd, *User) error

	// Read executes a read plugin command.
	Read(Cmd, *User) (*Reply, error)

	// TxHook executes a plugin hook using a database transaction.
	TxHook(*sql.Tx, HookT, Cmd, *User) error

	// TxWrite executes a write plugin command using a database transaction.
	TxWrite(*sql.Tx, Cmd, *User) (*Reply, error)

	// TxRead executes a read plugin command using a database transaction.
	TxRead(*sql.Tx, Cmd, *User) (*Reply, error)
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
	Session    Session
	PluginData PluginData
}

type Session struct {
	value   string // JSON encoded
	updated bool
}

func NewSession(value string) Session {
	return Session{
		value: value,
	}
}

func (s *Session) Value() string {
	return s.value
}

func (s *Session) SetValue(value string) {
	s.value = value
	s.updated = true
}

func (s *Session) Updated() bool {
	return s.updated
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

func NewPluginData(clearText, encrypted []byte) PluginData {
	return PluginData{
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
