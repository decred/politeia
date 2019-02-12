package commands

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/decred/politeia/politeiawww/database"
)

const MigrateHelpMsg = `migrate`

type MigrateCmd struct{}

func (cmd *MigrateCmd) Execute(args []string) error {

	// lastPaywallIndex will hold the biggest paywall index as we iterate
	// over the users records.
	var lastPaywallIndex uint64

	err := db.GetAll(func(key string, value []byte) error {
		if database.IsUserRecord(key) {
			user, err := migrateUser(key, value)
			if err != nil {
				return fmt.Errorf("migrate user %v: %v", key, err)
			}

			// Update lastPaywallIndex if needed.
			if user.PaywallAddressIndex > lastPaywallIndex {
				lastPaywallIndex = user.PaywallAddressIndex
			}
		}

		return nil
	})
	if err != nil {
		return err
	}

	// Update LastPaywallAddressIndex into the database.
	p, err := database.EncodeLastPaywallAddressIndex(database.LastPaywallAddressIndex{
		Index: lastPaywallIndex,
	})
	if err != nil {
		return fmt.Errorf("could not encode last paywall address index: %v", err)
	}
	err = db.Put(database.LastPaywallAddressIndexKey, p)
	if err != nil {
		return fmt.Errorf("could not insert paywall index %v", err)
	}

	// Update database version record.
	p, err = database.EncodeVersion(database.Version{
		Version: database.DatabaseVersion,
		Time:    time.Now().Unix(),
	})
	if err != nil {
		return fmt.Errorf("could not encode version record %v", err)
	}

	err = db.Put(database.DatabaseVersionKey, p)
	if err != nil {
		return fmt.Errorf("could not insert version record %v", err)
	}

	fmt.Printf("Database successfully migrated to version %v", database.DatabaseVersion)

	return nil
}

func migrateUser(key string, value []byte) (*database.User, error) {
	var user database.User

	// Decode user.
	err := json.Unmarshal(value, &user)
	if err != nil {
		return nil, fmt.Errorf("User cannot be decoded %v", err)
	}

	// Check if user key is ID, change it otherwise.
	newKey := key
	if key != user.ID.String() {
		newKey = user.ID.String()
	}

	// Make sure the user record has a field for
	// record type and version.
	p, err := database.EncodeUser(user)
	if err != nil {
		return nil, fmt.Errorf("Cannot encode user %v", err)
	}

	// Write the migrated user record into the database.
	err = db.Put(newKey, p)
	if err != nil {
		return nil, fmt.Errorf("Cannot insert user into the database: %v", err)
	}

	// If the old user key wasn't the ID, remove the record under
	// the previous key.
	if newKey != key {
		err = db.Remove(key)
		if err != nil {
			return nil, fmt.Errorf("Cannot remove user from the database: %v", err)
		}
	}

	return &user, nil
}
