package commands

import (
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/decred/politeia/util"

	"github.com/decred/politeia/politeiawww/database"
)

const DumpCmdHelpMsg = `dump false ~/.politeiawww`

type DumpCmd struct {
	Args struct {
		OutputDir string
	} `positional-args:"true"`
}

func (cmd *DumpCmd) Execute(args []string) error {

	snapshot, err := db.GetSnapshot()
	if err != nil {
		return fmt.Errorf("GetSnapshot: %v", err)
	}

	p, err := database.EncodeSnapshot(*snapshot)
	if err != nil {
		return err
	}

	outputdir := util.CleanAndExpandPath(cmd.Args.OutputDir, cfg.HomeDir)
	file := filepath.Join(outputdir, "dump.json")

	err = ioutil.WriteFile(file, p, 0600)
	if err != nil {
		return err
	}

	fmt.Printf("dump file saved in %v", file)

	return nil
}
