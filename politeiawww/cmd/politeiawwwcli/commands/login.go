package commands

import "github.com/decred/politeia/politeiawww/api/v1"

type LoginCmd struct {
	Args struct {
		Email    string `positional-arg-name:"email"`
		Password string `positional-arg-name:"password"`
	} `positional-args:"true" required:"true"`
}

func (cmd *LoginCmd) Execute(args []string) error {
	email := cmd.Args.Email
	password := cmd.Args.Password

	// Fetch CSRF tokens
	_, err := c.Version()
	if err != nil {
		return err
	}

	// Setup login request
	l := &v1.Login{
		Email:    email,
		Password: DigestSHA3(password),
	}

	// Print request details
	err = Print(l, cfg.Verbose, cfg.RawJSON)
	if err != nil {
		return err
	}

	// Send request
	lr, err := c.Login(l)
	if err != nil {
		return err
	}

	// Print response details
	return Print(lr, cfg.Verbose, cfg.RawJSON)
}
