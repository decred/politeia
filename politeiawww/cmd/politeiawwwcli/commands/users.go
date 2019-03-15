// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

import (
	"github.com/decred/politeia/politeiawww/api/v1"
)

// UsersCmd retreives a list of users that have been filtered using the
// specified filtering params.
type UsersCmd struct {
	Email    string  `long:"email"`    // Email filter
	Username string  `long:"username"` // Username filter
	PublicKey string `long:"pubkey"` // Username filter
}

// Execute executes the users command.
func (cmd *UsersCmd) Execute(args []string) error {
	u := v1.Users{
		Email:     cmd.Email,
		Username:  cmd.Username,
		PublicKey: cmd.PublicKey,
	}

	ur, err := client.Users(&u)
	if err != nil {
		return err
	}
	return printJSON(ur)
}

// usersHelpMsg is the output of the help command when 'users' is specified.
const usersHelpMsg = `users [flags]

Fetch a list of users, optionally filtering by email and/or username.

Arguments: None

Flags:
  --email       (string, optional)   Email filter
  --username    (string, optional)   Username filter

Example:
users --email=user@example.com --username=user

Result:
{
  "totalusers":    (uint64)  Total number of all users in the database
  "totalmatches":  (uint64)  Total number of users that match the filters
  "users": [
    {
      "id":        (string)  User id
      "email":     (string)  User email address
      "username":  (string)  Username
    }
  ]
}`
