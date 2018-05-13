package commands

import (
	"fmt"

	"github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/cmd/politeiawwwcli/config"
)

type GetvettedCmd struct {
	Before string `long:"before" optional:"true" description:"A proposal censorship token; if provided, the page of proposals returned will end right before the proposal whose token is provided."`
	After  string `long:"after" optional:"true" description:"A proposal censorship token; if provided, the page of proposals returned will end right after the proposal whose token is provided."`
}

func (cmd *GetvettedCmd) Execute(args []string) error {
	if cmd.Before != "" && cmd.After != "" {
		return fmt.Errorf(config.ErrorBeforeAfterFlags)
	}

	v := v1.GetAllVetted{}
	if cmd.Before != "" {
		v.Before = cmd.Before
	}

	if cmd.After != "" {
		v.After = cmd.After
	}

	_, err := Ctx.GetVetted(v)
	return err
}
