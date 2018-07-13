package commands

import (
	"fmt"
	"github.com/decred/politeia/politeiawww/cmd/politeiawwwcli/config"
)

type LoginCmd struct {
	Args struct {
		Email    string `positional-arg-name:"email"`
		Password string `positional-arg-name:"password"`
	} `positional-args:"true" required:"true"`
}

func (cmd *LoginCmd) Execute(args []string) error {
	_, id, err := Ctx.Login(cmd.Args.Email, cmd.Args.Password)
	if err != nil {
		return err
	}

	// save the user identity to HomeDir so it can be reused for subsequent commands
	id.Save(config.UserIdentityFile)
	if config.Verbose {
		fmt.Printf("User identity saved to: %v\n", config.UserIdentityFile)
	}

	// persist session cookie
	ck, err := Ctx.Cookies(config.Host)
	if err != nil {
		return err
	}

	err = config.SaveCookies(ck)
	return err

}
