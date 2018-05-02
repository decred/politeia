package commands

import (
	"fmt"

	"github.com/decred/politeia/politeiawww/cmd/politeiawwwcli/config"
)

type NewproposalCmd struct{}

func (cmd *NewproposalCmd) Execute(args []string) error {
	if config.UserIdentity == nil {
		return fmt.Errorf(config.ErrorNoUserIdentity)
	}

	_, err := Ctx.NewProposal(config.UserIdentity)
	return err
}
