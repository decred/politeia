package commands

import (
	"fmt"

	"github.com/decred/politeia/politeiawww/api/cms/v1"
)

type InviteNewUserCmd struct {
	Args struct {
		Email string `positional-arg-name:"email"`
	} `positional-args:"true" required:"true"`
}

func (cmd *InviteNewUserCmd) Execute(args []string) error {
	email := cmd.Args.Email

	if email == "" {
		return fmt.Errorf("invalid credentials: you must either specify user " +
			"email")
	}

	// Fetch CSRF tokens
	_, err := client.Version()
	if err != nil {
		return fmt.Errorf("Version: %v", err)
	}

	inu := &v1.InviteNewUser{
		Email: cmd.Args.Email,
	}

	// Print request details
	err = printJSON(inu)
	if err != nil {
		return err
	}

	// Send request
	inur, err := client.InviteNewUser(inu)
	if err != nil {
		return fmt.Errorf("InviteNewUser: %v", err)
	}

	// Print response details
	err = printJSON(inur)
	if err != nil {
		return err
	}

	return nil
}
