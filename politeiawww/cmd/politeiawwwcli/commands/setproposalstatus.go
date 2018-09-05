package commands

import (
	"fmt"

	"github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/cmd/politeiawwwcli/config"
)

type SetproposalstatusCmd struct {
	Args struct {
		Token   string `positional-arg-name:"token" required:"true" description:"Proposal censorship record token"`
		Status  int    `positional-arg-name:"status" required:"true" description:"Proposal status code"`
		Message string `positional-arg-name:"message" description:"Status change message (required if censoring proposal)"`
	} `positional-args:"true"`
}

func (cmd *SetproposalstatusCmd) Execute(args []string) error {
	if config.UserIdentity == nil {
		return fmt.Errorf(config.ErrorNoUserIdentity)
	}

	var ps v1.PropStatusT = v1.PropStatusT(cmd.Args.Status)
	if ps == v1.PropStatusCensored && cmd.Args.Message == "" {
		return fmt.Errorf("Status change message required when censoring a proposal")
	}

	_, err := Ctx.SetPropStatus(config.UserIdentity, cmd.Args.Token, ps, cmd.Args.Message)
	return err
}
