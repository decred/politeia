package commands

import (
	"encoding/hex"
	"fmt"

	"github.com/decred/politeia/politeiawww/cmd/politeiawwwcli/config"
)

type VerifyuserArgs struct {
	Email string `positional-arg-name:"email"`
	Token string `positional-arg-name:"token"`
}

type VerifyuserCmd struct {
	Args VerifyuserArgs `positional-args:"true" required:"true"`
}

func (cmd *VerifyuserCmd) Execute(args []string) error {
	if config.UserIdentity == nil {
		return fmt.Errorf(config.ErrorNoUserIdentity)
	}

	sig := config.UserIdentity.SignMessage([]byte(cmd.Args.Token))
	err := Ctx.VerifyNewUser(cmd.Args.Email, cmd.Args.Token,
		hex.EncodeToString(sig[:]))
	return err
}
