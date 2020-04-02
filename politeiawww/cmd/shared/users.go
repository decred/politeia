// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package shared

import (
	"github.com/thi4go/politeia/politeiawww/api/www/v1"
)

// UsersCmd retreives a list of users that have been filtered using the
// specified filtering params.
type UsersCmd struct {
	Email     string `long:"email"`    // Email filter
	Username  string `long:"username"` // Username filter
	PublicKey string `long:"pubkey"`   // Username filter
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
	return PrintJSON(ur)
}

// UsersHelpMsg is the output of the help command when 'users' is specified.
const UsersHelpMsg = `users [flags]

Fetch a list of users. If logged in as admin, users returns a list 
of all users, optionally filtering by username, email or public key. Partial 
matches are returned. If not logged in (or logged in as non admin) users 
returns a list of users filtered by username or public key, with only exact
matches returned. 

Arguments: None

Flags:
  --email       (string, optional)   Email filter
  --username    (string, optional)   Username filter
  --pubkey      (string, optional)   Public Key


Example (Admin):
users --email=user@example.com --username=user --pubkey=0b2283a91f6bf95f2c121
14c7c1259c1396756bea4f64be43fe0f73b383bdf92

Result (Admin):
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
}

Example (non Admin):
--pubkey=0b2283a91f6bf95f2c12114c7c1259c1396756bea4f64be43fe0f73b383bdf92

Result (Non admin):
{
  "users": [
    {
      "id": 		(string)  User id
      "username": 	(string)  Username
    }
  ]
}
`
