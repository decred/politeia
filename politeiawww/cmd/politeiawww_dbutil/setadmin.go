package main

import (
	"fmt"
	"strings"

	_ "github.com/jinzhu/gorm/dialects/postgres"
)

// SetAdminCmd is a command to set a given user as admin
type SetAdminCmd struct {
	Args struct {
		Username string `positional-arg-name:"username"`
		Boolean  string `positional-arg-name:"true/false"`
	} `positional-args:"true" required:"true"`
}

// Execute setadmin command.
func (cmd *SetAdminCmd) Execute(args []string) error {
	err := connectToDatabase()
	if err != nil {
		return err
	}
	defer userDB.Close()

	username := cmd.Args.Username
	isAdmin := (strings.ToLower(cmd.Args.Boolean) == "true" || cmd.Args.Boolean == "1")

	u, err := userDB.UserGetByUsername(username)
	if err != nil {
		return err
	}

	u.Admin = isAdmin

	err = userDB.UserUpdate(*u)
	if err != nil {
		return err
	}

	fmt.Printf("User with username '%v' admin status updated "+
		"to %v\n", username, isAdmin)

	return nil
}

// setAdminHelpMsg is the output of the help command when 'setadmin' is
// specified.
const setAdminHelpMsg = `setadmin --database=<name> "username" boolean 

Set the admin flag for a user.
This command requires a DB connection. You can use either 'leveldb' or
'cockroachdb'.


Arguments:
1. username      (string, required)   User username
2. boolean      (string, required)		true/false
`
