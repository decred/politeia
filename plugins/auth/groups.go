// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package auth

// The following list contains the default auth plugin user groups.
const (
	// publicUser represents a public user. Commands that are assigned this
	// user group can be run freely by any client. The client does not need to
	// have a valid user session. User session data is not checked for public
	// commands.
	publicUser = "public"

	// standardUser is the default user group that is assigned to an account on
	// creation.
	standardUser = "standard"

	// superUser is an app superuser. This group is able to assign any group to
	// any user.
	//
	// The only way to add a user to the superuser group is to have the sysadmin
	// update the database directly.
	superUser = "superuser"
)

func (p *authp) validGroup(group string) bool {
	return false
}

func (p *authp) userCanAssignGroup(u user, group string) bool {
	return false
}
