package main

import (
	"fmt"

	"github.com/decred/politeia/politeiawww/user"
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

// VerifyIdentitiesCmd verify user's identities.
type VerifyIdentitiesCmd struct {
	Args struct {
		Username string `positional-arg-name:"username"`
	} `positional-args:"true" required:"true"`
}

// Execute runs the verifyidentities command
func (cmd *VerifyIdentitiesCmd) Execute(args []string) error {

	err := connectToDatabase()
	if err != nil {
		return err
	}
	defer userDB.Close()

	u, err := userDB.UserGetByUsername(cmd.Args.Username)
	if err != nil {
		return fmt.Errorf("UserGetByUsername(%v): %v",
			cmd.Args.Username, err)
	}

	// Verify inactive identities. There should only ever be one
	// inactive identity at a time. If more than one inactive identity
	// is found, deactivate all of them since it can't be determined
	// which one is the most recent.
	inactive := make(map[string]user.Identity, len(u.Identities)) // [pubkey]Identity
	for _, v := range u.Identities {
		if v.IsInactive() {
			inactive[v.String()] = v
		}
	}
	switch len(inactive) {
	case 0:
		fmt.Printf("0 inactive identities found; this is ok\n")
	case 1:
		fmt.Printf("1 inactive identity found; this is ok\n")
	default:
		fmt.Printf("%v inactive identities found\n", len(inactive))
		for _, v := range inactive {
			fmt.Printf("%v\n", v.String())
		}

		fmt.Printf("deactivating all inactive identities\n")

		for i, v := range u.Identities {
			if !v.IsInactive() {
				// Not an inactive identity
				continue
			}
			fmt.Printf("deactivating: %v\n", v.String())
			u.Identities[i].Deactivate()
		}
	}

	// Verify active identities. There should only ever be one active
	// identity at a time.
	active := make(map[string]user.Identity, len(u.Identities)) // [pubkey]Identity
	for _, v := range u.Identities {
		if v.IsActive() {
			active[v.String()] = v
		}
	}
	switch len(active) {
	case 0:
		fmt.Printf("0 active identities found; this is ok\n")
	case 1:
		fmt.Printf("1 active identity found; this is ok\n")
	default:
		fmt.Printf("%v active identities found\n", len(active))
		for _, v := range active {
			fmt.Printf("%v\n", v.String())
		}

		fmt.Printf("deactivating all but the most recent active identity\n")

		// Find most recent active identity
		var pubkey string
		var ts int64
		for _, v := range active {
			if v.Activated > ts {
				pubkey = v.String()
				ts = v.Activated
			}
		}

		// Deactivate all but the most recent active identity
		for i, v := range u.Identities {
			if !v.IsActive() {
				// Not an active identity
				continue
			}
			if pubkey == v.String() {
				// Most recent active identity
				continue
			}
			fmt.Printf("deactivating: %v\n", v.String())
			u.Identities[i].Deactivate()
		}
	}

	// Update user
	err = userDB.UserUpdate(*u)
	if err != nil {
		return fmt.Errorf("UserUpdate: %v", err)
	}

	return nil
}

// verifyIdentitiesHelpMsg is the output of the help command when 'verifyidentities' is
// specified.
const verifyIdentitiesHelpMsg = `verifyidentities "username"

Verify a user's identities do not violate any politeia rules. Invalid identities are fixed.

Must use cockroachdb Database

Arguments:
1. username      (string, required)   User username
`
