// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package app

// Hook represents an app hook.
//
// Pre hooks allow plugins to add plugin specific validation onto external
// plugin commands.
//
// Post hooks allow plugins to update caches with any necessary changes that
// result from the execution of the command.
type Hook string

const (
	// HookInvalid is an invalid hook.
	HookInvalid Hook = "invalid"

	// HookPreNewUser is the hook that is executed before a NewUser command
	// is executed.
	HookPreNewUser Hook = "pre-new-user"

	// HookPostNewUser is the hook that is executed after the successful
	// execution of a NewUser command.
	HookPostNewUser Hook = "post-new-user"

	// HookPreWrite is the hook that is executed before a plugin write command
	// is executed.
	HookPreWrite Hook = "pre-write"

	// HookPostWrite is the hook that is executed after the successful execution
	// of a plugin write command.
	HookPostWrite Hook = "post-write"
)
