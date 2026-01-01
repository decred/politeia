// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package auth

import (
	"database/sql"

	"github.com/dajohi/goemail"
	"github.com/decred/politeia/app"
)

// authp represents the auth plugin.
//
// authp satisfies the app.Plugin interface.
// authp satisfies the app.AuthManager interface.
type authp struct {
	db       *sql.DB
	settings settings

	smtp         *goemail.SMTP
	emailName    string // From email name
	emailAddress string // From email address

	// groups contains all of the valid user groups and who is allowed to
	// assign those user groups. The super user can assign any user group
	// regarless of how they are configured.
	groups map[string][]string // [userGroup]assignedBy

	// perms contains the user groups that are allowed to execute each plugin
	// command.
	perms map[string]map[string]struct{} // [cmd][userGroup]
}

// Args contains the arguments that are required by he New function that
// initializes the auth plugin.
type Args struct {
	Settings     []app.Setting
	DB           *sql.DB
	SMTP         *goemail.SMTP
	EmailName    string // From email name
	EmailAddress string // From email address
	Groups       []app.UserGroup
}

// New returns a new authp.
func New(a Args) (*authp, error) {
	s, err := parseSettings(a.Settings)
	if err != nil {
		return nil, err
	}

	groups := map[string][]string{
		// Default user groups
		publicUser:   {},
		standardUser: {},
		superUser:    {},
	}
	for _, v := range a.Groups {
		groups[v.Group] = v.AssignedBy
	}

	p := &authp{
		db:           a.DB,
		settings:     *s,
		perms:        make(map[string]map[string]struct{}, 256),
		smtp:         a.SMTP,
		emailName:    a.EmailName,
		emailAddress: a.EmailAddress,
		groups:       groups,
	}

	err = p.setupDB()
	if err != nil {
		return nil, err
	}
	return p, nil
}
