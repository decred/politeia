package commands

import (
	"fmt"

	"github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/cmd/politeiawwwcli/config"
)

type SetproposalstatusCmd struct {
	Args struct {
		Token  string `positional-arg-name:"token"`
		Status int    `positional-arg-name:"status"`
	} `positional-args:"true" required:"true"`
}

func (cmd *SetproposalstatusCmd) Execute(args []string) error {
	if config.UserIdentity == nil {
		return fmt.Errorf(config.ErrorNoUserIdentity)
	}
	var ps v1.PropStatusT = v1.PropStatusT(cmd.Args.Status)
	_, err := Ctx.SetPropStatus(config.UserIdentity, cmd.Args.Token, ps)
	return err
}
