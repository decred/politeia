package main

import (
	"fmt"

	_ "github.com/jinzhu/gorm/dialects/postgres"
)

// ResetTotpCmd adds credits to the given user
type ResetTotpCmd struct {
	Args struct {
		Username string `positional-arg-name:"username"`
	} `positional-args:"true" required:"true"`
}

// Execute addcredits command
func (cmd *ResetTotpCmd) Execute(args []string) error {

	err := connectToDatabase()
	if err != nil {
		return err
	}
	defer userDB.Close()

	username := cmd.Args.Username
	u, err := userDB.UserGetByUsername(username)
	if err != nil {
		return err
	}

	u.TOTPLastUpdated = nil
	u.TOTPSecret = ""
	u.TOTPType = 0
	u.TOTPVerified = false

	err = userDB.UserUpdate(*u)
	if err != nil {
		return err
	}

	fmt.Printf("User with username '%v' reset totp\n", username)

	return nil
}

// resetTotpHelpMsg is the output of the help command when 'resettotp' is
// specified.
const resetTotpHelpMsg = `resettotp "username"

Reset a user's totp settings in case they are locked out and confirm identity.

Arguments:
1. username      (string, required)   User username
`
