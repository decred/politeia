package commands

import (
	"fmt"

	"github.com/decred/politeia/politeiawww/cmd/politeiawwwcli/config"
)

type UpdateuserkeyCmd struct{}

func (cmd *UpdateuserkeyCmd) Execute(args []string) error {
	// get user's email address
	lr, err := Ctx.Me()
	if err != nil {
		return err
	}

	// create new key from email
	id, err := Ctx.CreateNewKey(lr.Email)
	if err != nil {
		return err
	}

	// save user identity to HomeDir
	id.Save(config.UserIdentityFile)
	fmt.Printf("User identity saved to: %v\n", config.UserIdentityFile)

	return nil
}
