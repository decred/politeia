// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

import "database/sql"

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
	NewUser(*sql.Tx, WriteArgs) (*Reply, error)
}
