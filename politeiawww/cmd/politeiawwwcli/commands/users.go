package commands

import (
	"github.com/decred/politeia/politeiawww/api/v1"
)

// Help message displayed for the command 'politeiawwwcli help users'
var UsersCmdHelpMsg = `users "email" "username"

Fetch a list of users, optionally filtering by email and/or username.

Arguments:
1. email       (string, optional)   Email of user
2. username    (string, optional)   Username of user 

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

type UsersCmd struct {
	Email    string `long:"email" optional:"true" description:"Email query"`
	Username string `long:"username" optional:"true" description:"Username query"`
}

func (cmd *UsersCmd) Execute(args []string) error {
	u := v1.Users{
		Email:    cmd.Email,
		Username: cmd.Username,
	}

	ur, err := c.Users(&u)
	if err != nil {
		return err
	}
	return Print(ur, cfg.Verbose, cfg.RawJSON)
}
