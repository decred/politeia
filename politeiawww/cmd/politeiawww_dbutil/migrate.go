package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/politeiawww/user/cockroachdb"
	"github.com/decred/politeia/politeiawww/user/localdb"
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

// MigrateCmd is a command to migrate leveldb users to cockroach
type MigrateCmd struct{}

// Execute runs the migrate command
func (cmd *MigrateCmd) Execute(args []string) error {
	// Connect to LevelDB
	dbDir := filepath.Join(cfg.Datadir, network)
	_, err := os.Stat(dbDir)
	if err != nil {
		if os.IsNotExist(err) {
			err = fmt.Errorf("leveldb dir not found: %v", dbDir)
		}
		return err
	}

	ldb, err := localdb.New(dbDir)
	if err != nil {
		return err
	}

	// Connect to CockroachDB
	err = validateCockroachParams()
	if err != nil {
		return fmt.Errorf("new leveldb: %v", err)
	}
	cdb, err := cockroachdb.New(cfg.Host, network, cfg.RootCert,
		cfg.ClientCert, cfg.ClientKey, cfg.EncryptionKey)
	if err != nil {
		return fmt.Errorf("new cockroachdb: %v", err)
	}
	defer cdb.Close()

	fmt.Printf("LevelDB     : %v\n", dbDir)
	fmt.Printf("CockroachDB : %v %v\n", cfg.Host, network)
	fmt.Printf("Migrating records from LevelDB to CockroachDB...\n")

	// Migrate LevelDB records to CockroachDB
	var users []user.User
	var paywallIndex uint64
	var userCount int

	// populates the user slice from leveldb users
	err = ldb.AllUsers(func(u *user.User) {
		users = append(users, *u)
	})
	if err != nil {
		return fmt.Errorf("leveldb allusers request: %v", err)
	}

	// Make sure the migration went ok.
	if len(users) == 0 {
		return fmt.Errorf("no users found in leveldb")
	}

	for i := 0; i < len(users); i++ {

		u := users[i]
		// Check if username already exists in db. There was a
		// ~2 month period where a bug allowed for users to be
		// created with duplicate usernames.
		_, err = cdb.UserGetByUsername(u.Username)

		paywallIndex = u.PaywallAddressIndex
		switch err {
		case nil:
			for !errors.Is(err, user.ErrUserNotFound) {
				// Username is a duplicate. Allow for the username to be
				// updated here. The migration will fail if the username
				// is not unique.
				fmt.Printf("Username '%v' already exists. Username must be "+
					"updated for the following user before the migration can "+
					"continue.\n", u.Username)

				fmt.Printf("ID                 : %v\n", u.ID.String())
				fmt.Printf("Email              : %v\n", u.Email)
				fmt.Printf("Username           : %v\n", u.Username)
				fmt.Printf("Input new username : ")

				var input string
				r := bufio.NewReader(os.Stdin)
				input, err = r.ReadString('\n')
				if err != nil {
					return err
				}

				username := strings.TrimSuffix(input, "\n")
				u.Username = strings.ToLower(strings.TrimSpace(username))
				_, err = cdb.UserGetByUsername(u.Username)
			}

			fmt.Printf("Username updated to '%v'\n", u.Username)

		case user.ErrUserNotFound:
			// Username doesn't exist; continue
		default:
			return err
		}

		err = cdb.InsertUser(u)
		if err != nil {
			return fmt.Errorf("migrate user '%v': %v",
				u.ID, err)
		}
		userCount++
	}

	fmt.Printf("Users migrated : %v\n", userCount)
	fmt.Printf("Paywall index  : %v\n", paywallIndex)
	fmt.Printf("Done!\n")

	return nil
}

// migrateHelpMsg is the output of the help command when 'migrate' is
// specified.
const migrateHelpMsg = `migrate

Create user stubs for the public keys in a politeia repo

No arguments.
`
