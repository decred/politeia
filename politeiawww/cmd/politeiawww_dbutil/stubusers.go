package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/util"
	"github.com/google/uuid"
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

// StubUsersCmd command to create stub users
type StubUsersCmd struct {
	Args struct {
		ImportDir string `positional-arg-name:"importdir"`
	} `positional-args:"true" required:"true"`
}

// Execute runs the stubuser command
func (cmd *StubUsersCmd) Execute(args []string) error {
	err := connectToDatabase()
	if err != nil {
		return err
	}
	defer userDB.Close()

	// Parse import directory
	importDir := util.CleanAndExpandPath(cmd.Args.ImportDir)
	_, err = os.Stat(importDir)
	if err != nil {
		return err
	}

	// Walk import directory and compile all unique public
	// keys that are found.
	fmt.Printf("Walking import directory...\n")
	pubkeys := make(map[string]struct{})
	err = filepath.Walk(importDir,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			// Skip directories
			if info.IsDir() {
				return nil
			}

			switch info.Name() {
			case commentsJournalFilename:
				err := replayCommentsJournal(path, pubkeys)
				if err != nil {
					return err
				}
			}

			return nil
		})
	if err != nil {
		return fmt.Errorf("walk import dir: %v", err)
	}

	fmt.Printf("Stubbing users...\n")

	// update users on database
	var i int
	for k := range pubkeys {
		username := fmt.Sprintf("dbutil_user%v", i)
		email := username + "@example.com"
		id, err := util.IdentityFromString(k)
		if err != nil {
			return err
		}

		err = userDB.UserNew(user.User{
			ID:             uuid.New(),
			Email:          email,
			Username:       username,
			HashedPassword: []byte("password"),
			Admin:          false,
			Identities: []user.Identity{
				{
					Key:       id.Key,
					Activated: time.Now().Unix(),
				},
			},
		})
		if err != nil {
			return err
		}

		i++
	}

	fmt.Printf("Done!\n")
	return nil
}

// stubUsersHelpMsg is the output of the help command when 'stubusers' is
// specified.
const stubUsersHelpMsg = `stubusers "importdir"

Create user stubs for the public keys in a politeia repo.
Requires a database flag.

Arguments:
1. importdir      (string, required)   The import directory
`
