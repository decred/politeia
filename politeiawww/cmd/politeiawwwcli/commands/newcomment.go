package commands

import (
	"fmt"

	"github.com/decred/politeia/politeiawww/cmd/politeiawwwcli/config"
)

type NewcommentCmd struct {
	Args struct {
		Token    string `positional-arg-name:"token" required:"true"`
		Comment  string `positional-arg-name:"comment" required:"true"`
		ParentID string `positional-arg-name:"parentID"`
	} `positional-args:"true"`
}

func (cmd *NewcommentCmd) Execute(args []string) error {
	if config.UserIdentity == nil {
		return fmt.Errorf(config.ErrorNoUserIdentity)
	}

	_, err := Ctx.Comment(config.UserIdentity, cmd.Args.Token, cmd.Args.Comment,
		cmd.Args.ParentID)
	return err
}
