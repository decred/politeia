package commands

import (
	"fmt"

	"github.com/decred/politeia/politeiawww/cmd/politeiawwwcli/config"
)

type StartvoteCmd struct {
	Args struct {
		Token string `positional-arg-name:"token"`
	} `positional-args:"true" required:"true"`
}

func (cmd *StartvoteCmd) Execute(args []string) error {
	if config.UserIdentity == nil {
		return fmt.Errorf(config.ErrorNoUserIdentity)
	}
	_, err := Ctx.StartVote(config.UserIdentity, cmd.Args.Token)
	return err
}
