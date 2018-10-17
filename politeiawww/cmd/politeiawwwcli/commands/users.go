package commands

import (
	"github.com/decred/politeia/politeiawww/api/v1"
)

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
