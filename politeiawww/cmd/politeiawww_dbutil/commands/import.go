package commands

import (
	"fmt"
	"io/ioutil"

	"github.com/decred/politeia/politeiawww/database"
	"github.com/decred/politeia/util"
)

const ImportHelpMsg = `import "filename"`

type ImportCmd struct {
	Args struct {
		FileName string `positional-arg-name:"filename" required:"true" description:"The file containing the database snapshot"`
	} `positional-args:"true"`
}

func (cmd *ImportCmd) Execute(args []string) error {
	filename := util.CleanAndExpandPath(cmd.Args.FileName, cfg.HomeDir)

	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("Cannot import file %v: %v", filename, err)
	}

	snapshot, err := database.DecodeSnapshot(b)
	if err != nil {
		return fmt.Errorf("Cannot decode Snapshot: %v", err)
	}

	err = db.BuildFromSnapshot(*snapshot)
	if err != nil {
		return fmt.Errorf("Cannot build db from snapshot: %v", err)
	}

	fmt.Printf("Database successfully imported!")
	return nil
}
