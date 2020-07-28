// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package plugins

import "errors"

type HookT int

const (
	// Plugin hooks
	HookInvalid             HookT = 0
	HookPostNewRecord       HookT = 1
	HookPostEditRecord      HookT = 2
	HookPostEditMetadata    HookT = 3
	HookPostSetRecordStatus HookT = 4
)

var (
	// Human readable plugin hooks
	Hook = map[HookT]string{
		HookPostNewRecord:       "post new record",
		HookPostEditRecord:      "post edit record",
		HookPostEditMetadata:    "post edit metadata",
		HookPostSetRecordStatus: "post set record status",
	}

	// ErrInvalidPluginCmd is emitted when an invalid plugin command is
	// used.
	ErrInvalidPluginCmd = errors.New("invalid plugin command")
)

// Plugin provides an interface for the backend to use when interacting with
// plugins.
type Plugin interface {
	// Perform plugin setup
	Setup() error

	// Execute a plugin command
	Cmd(cmd, payload string) (string, error)

	// Execute a plugin hook
	Hook(h HookT, payload string) error

	// Perform a plugin file system check
	Fsck() error
}
