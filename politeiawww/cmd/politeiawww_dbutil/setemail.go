package main

import (
	"fmt"
	"strings"

	_ "github.com/jinzhu/gorm/dialects/postgres"
)

// SetEmailCmd is a command to set a new email for given user
type SetEmailCmd struct {
	Args struct {
		Username string `positional-arg-name:"username"`
		Email    string `positional-arg-name:"email"`
	} `positional-args:"true" required:"true"`
}

// Execute setemail command
func (cmd *SetEmailCmd) Execute(args []string) error {
	if cfg.Database != "cockroachdb" {
		return fmt.Errorf("this cannot be used without the cockroachdb database")
	}

	err := connectToDatabase()
	if err != nil {
		return err
	}
	defer userDB.Close()

	username := strings.ToLower(cmd.Args.Username)
	newEmail := strings.ToLower(cmd.Args.Email)

	u, err := userDB.UserGetByUsername(username)
	if err != nil {
		return err
	}

	u.Email = newEmail

	err = userDB.UserUpdate(*u)
	if err != nil {
		return err
	}

	fmt.Printf("User with username '%v' email successfully updated to '%v'\n",
		username, newEmail)
	fmt.Printf("politeiawww MUST BE restarted so the user email memory cache " +
		"gets updated; politeiad is fine and does not need to be restarted\n")

	return nil
}

// setEmailHelpMsg is the output of the help command when 'setemail' is
// specified.
const setEmailHelpMsg = `setemail "username" "email" 

Set a new email for given username's user

Arguments:
1. username      (string, required)   User username
2. email         (string, required)		New email
`
