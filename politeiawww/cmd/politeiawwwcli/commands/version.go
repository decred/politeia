package commands

import (
	"github.com/decred/politeia/politeiawww/cmd/politeiawwwcli/config"
)

type VersionCmd struct{}

func (cmd *VersionCmd) Execute(args []string) error {
	_, err := Ctx.Version()
	if err != nil {
		return err
	}

	// CSRF protection works via double-submit method. One token is stored in the
	// cookie. A different token is sent via the header. Both tokens must be
	// persisted between cli commands.

	// persist CSRF header token
	config.SaveCsrf(Ctx.Csrf())

	// persist session cookie
	ck, err := Ctx.Cookies(config.Host)
	if err != nil {
		return err
	}
	err = config.SaveCookies(ck)

	return err
}
