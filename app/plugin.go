// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package app

import (
	"database/sql"
	"fmt"

	"github.com/dajohi/goemail"
)

// Plugin represents an app plugin.
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
}

// PluginArgs contains the arguments that are passed to a plugin on
// initialization.
type PluginArgs struct {
	Settings     []Setting
	DB           *sql.DB
	SMTP         *goemail.SMTP
	EmailName    string // From email name
	EmailAddress string // From email address
}

// Setting represents a configurable plugin setting.
//
// The value can either contain a single value or multiple values. Multiple
// values will be formatted as a JSON encoded []string.
type Setting struct {
	Name  string
	Value string
}

// CmdDetails contains summary information about a plugin command.
type CmdDetails struct {
	Plugin  string
	Version uint32 // Plugin API version
	Name    string
}

// String returns a string representation of the command.
func (c *CmdDetails) String() string {
	return fmt.Sprintf("%v-v%v-%v", c.Plugin, c.Version, c.Name)
}

// WriteArgs contain the arguments for the plugin write methods.
//
// Updates that are made to the Session during write command execution are
// persisted by the server on successful completion of the command.
type WriteArgs struct {
	Cmd     Cmd
	Session *Session
	UserID  string
}

func (a *WriteArgs) String() string {
	userID := a.UserID
	if userID == "" {
		userID = "no-user-id"
	}
	return fmt.Sprintf("%v %v", &a.Cmd, userID)
}

// ReadArgs contain the arguments for the plugin read methods.
type ReadArgs struct {
	Cmd    Cmd
	UserID string
}

func (a *ReadArgs) String() string {
	userID := a.UserID
	if userID == "" {
		userID = "no-user-id"
	}
	return fmt.Sprintf("%v %v", &a.Cmd, userID)
}

// HookArgs contains the arguments for the plugin hook methods.
type HookArgs struct {
	Type   Hook
	Cmd    Cmd
	Reply  *CmdReply
	UserID string
}

func (a *HookArgs) String() string {
	userID := a.UserID
	if userID == "" {
		userID = "no-user-id"
	}
	return fmt.Sprintf("%v %v %v", a.Type, &a.Cmd, userID)
}

// Cmd represents a plugin command.
type Cmd struct {
	Plugin  string
	Version uint32 // API version
	Name    string
	Payload string // JSON encoded
}

// String returns the string representation of a plugin command.
func (c *Cmd) String() string {
	return fmt.Sprintf("%v-v%v-%v", c.Plugin, c.Version, c.Name)
}

// CmdReply is the reply to a plugin command.
type CmdReply struct {
	Payload string // JSON encoded
}
