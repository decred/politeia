// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package auth

import (
	"encoding/json"

	"github.com/decred/politeia/app"
	v1 "github.com/decred/politeia/plugins/auth/v1"
)

// TODO I should keep all user data in a table locally for the auth plugin
// because the auth plugin needs to be able to access user data when a session
// does not exist yet, like when a user logs in.

// TODO get rid of the global user object. Only pass the user ID.

type user struct {
	ID          string
	Username    string
	Perms       []string
	ContactInfo []v1.ContactInfo
}

// userBlob contains the auth plugin user data that travels with the global
// user as a JSON encoded byte slice.
type userBlob struct {
	Perms []string
}

func decodeUser(u app.User) (*user, error) {
	var ub userBlob
	err := json.Unmarshal(u.Data(), &ub)
	if err != nil {
		return nil, err
	}
	return &user{
		ID:    u.ID.String(),
		Perms: ub.Perms,
	}, nil
}

// TODO
func (p *plugin) getUser(userID string) (*user, error) {
	return nil, nil
}
