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
	perms    map[string]map[string]struct{} // [cmd][userGroup]

	smtp         *goemail.SMTP
	emailName    string // From email name
	emailAddress string // From email address
}

// New returns a new authp.
func New(a app.PluginArgs) (*authp, error) {
	s, err := newSettings(a.Settings)
	if err != nil {
		return nil, err
	}
	p := &authp{
		db:           a.DB,
		settings:     *s,
		perms:        make(map[string]map[string]struct{}, 256),
		smtp:         a.SMTP,
		emailName:    a.EmailName,
		emailAddress: a.EmailAddress,
	}
	err = p.setupDB()
	if err != nil {
		return nil, err
	}
	return p, nil
}
