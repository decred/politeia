// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

import (
	"database/sql"
	"fmt"
)

// Plugin represents a politeia user plugin.
//
// Plugins are allowed to update the session values. Updated values will be
// persisted by the caller.
type Plugin interface {
	// ID returns the plugin ID.
	ID() string

	// Hook executes a plugin hook.
	Hook(h HookT, cmd Cmd, s *Session) error

	// Read executes a read plugin command.
	Read(cmd Cmd, s *Session) (*Reply, error)

	// TxHook executes a plugin hook using a database transaction.
	TxHook(tx *sql.Tx, h HookT, cmd Cmd, s *Session) error

	// TxWrite executes a write plugin command using a database transaction.
	TxWrite(tx *sql.Tx, cmd Cmd, s *Session) (*Reply, error)

	// TxRead executes a read plugin command using a database transaction.
	TxRead(tx *sql.Tx, cmd Cmd, s *Session) (*Reply, error)
}

type Session struct {
	Values map[interface{}]interface{}
}

type Cmd struct {
	Cmd     string
	Payload string // JSON encoded
}

type Reply struct {
	Payload string // JSON encoded
	Error   error
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
