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
	Hook(h HookT, cmd PluginCmd, s *Session) error

	// Write executes a write plugin command.
	Write(tx *sql.Tx, cmd PluginCmd, s *Session) (*PluginReply, error)

	// Read executes a read plugin command.
	Read(cmd PluginCmd, s *Session) (*PluginReply, error)
}

type Session struct {
	Values map[interface{}]interface{}
}

type PluginCmd struct {
	Cmd     string
	Payload string // JSON encoded
}

type PluginReply struct {
	Payload string // JSON encoded
}

type HookT string

const (
	HookInvalid   HookT = "invalid"
	HookPreWrite  HookT = "pre-write"
	HookPostWrite HookT = "post-write"
)

// PluginError is the reply that is returned when a plugin command encounters
// an error that was caused by the user.
type PluginError struct {
	ErrorCode    uint32 `json:"errorcode"`
	ErrorContext string `json:"errorcontext,omitempty"`
}

// Error satisfies the error interface.
func (e PluginError) Error() string {
	return fmt.Sprintf("plugin error code: %v", e.ErrorCode)
}
