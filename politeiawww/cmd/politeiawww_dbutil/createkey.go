package main

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/decred/politeia/util"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/marcopeereboom/sbox"
)

// CreateKeyCmd is the command to create new encryption keys
type CreateKeyCmd struct {
	Args struct {
		Destination string `positional-arg-name:"destination"`
	} `positional-args:"true"`
}

// Execute runs the createkey command
func (cmd *CreateKeyCmd) Execute(args []string) error {
	path := defaultEncryptionKey

	if cmd.Args.Destination != "" {
		path = util.CleanAndExpandPath(cmd.Args.Destination)
	}

	// Don't allow overwriting an existing key
	_, err := os.Stat(path)
	if err == nil {
		return fmt.Errorf("file already exists; cannot "+
			"overwrite %v", path)
	}

	// Create a new key
	k, err := sbox.NewKey()
	if err != nil {
		return err
	}

	// Write hex encoded key to file
	err = ioutil.WriteFile(path, []byte(hex.EncodeToString(k[:])), 0644)
	if err != nil {
		return err
	}

	fmt.Printf("Encryption key saved to: %v\n", path)

	// Zero out encryption key
	util.Zero(k[:])
	k = nil

	return nil
}

// createKeyHelpMsg is the output of the help command when 'createkey' is
// specified.
const createKeyHelpMsg = `createkey "destination"

Create a new encryption key that can be used to encrypt data at rest.

Arguments:
1. destination      (string)   Key destination (default osDataDir/politeiawww/sbox.key)
`
