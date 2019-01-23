package commands

import (
	"fmt"

	"github.com/decred/politeia/politeiawww/database"
)

type DBVersionCmd struct{}

const DBVersionHelpMsg = `dbversion`

func (cmd *DBVersionCmd) Execute(args []string) error {
	p, err := db.Get(database.DatabaseVersionKey)
	if err != nil {
		return fmt.Errorf("Could not get database version: %v", err)
	}

	v, err := database.DecodeVersion(p)
	if err != nil {
		return fmt.Errorf("Decode version: %v", err)
	}
	fmt.Printf("Databsase version: %d", v.Version)

	return nil
}
