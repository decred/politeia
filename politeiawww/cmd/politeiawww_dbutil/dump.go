package main

import (
	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/decred/politeia/politeiawww/user"
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

// DumpCmd dumps the content for a given username
type DumpCmd struct {
	Args struct {
		Username string `positional-arg-name:"username"`
	} `positional-args:"true"`
}

// Execute the dump command
func (cmd *DumpCmd) Execute(args []string) error {

	if cfg.Database != "leveldb" {
		return fmt.Errorf("dump command requires a 'leveldb' database (--database=leveldb)")
	}

	err := connectToDatabase()
	if err != nil {
		return err
	}
	defer userDB.Close()

	// If email is provided, only dump that user.
	username := cmd.Args.Username
	if username != "" {
		u, err := userDB.UserGetByUsername(username)

		if err != nil {
			return err
		}

		fmt.Printf("Key    : %v\n", username)
		fmt.Printf("Record : %v", spew.Sdump(u))
		return nil
	}

	err = userDB.AllUsers(func(u *user.User) {
		fmt.Printf("Key    : %v\n", u.Username)
		fmt.Printf("Record : %v\n", spew.Sdump(u))
	})
	if err != nil {
		return err
	}
	return nil
}

// dumpHelpMsg is the output of the help command when 'dump' is
// specified.
const dumpHelpMsg = `dump --database=leveldb "username" 

Dump the entire database or the contents of a specific user

Database must be leveldb (--database=leveldb)

Arguments:
1. username      (string, required)   User username
`
