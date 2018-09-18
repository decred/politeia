package commands

import "github.com/decred/politeia/politeiawww/api/v1"

type ChangeUsernameCmd struct {
	Args struct {
		Password    string `positional-arg-name:"password"`
		NewUsername string `positional-arg-name:"newusername"`
	} `positional-args:"true" required:"true"`
}

func (cmd *ChangeUsernameCmd) Execute(args []string) error {
	cu := &v1.ChangeUsername{
		Password:    DigestSHA3(cmd.Args.Password),
		NewUsername: cmd.Args.NewUsername,
	}

	// Print request details
	err := Print(cu, cfg.Verbose, cfg.RawJSON)
	if err != nil {
		return err
	}

	// Send request
	cur, err := c.ChangeUsername(cu)
	if err != nil {
		return err
	}

	// Print response details
	return Print(cur, cfg.Verbose, cfg.RawJSON)
}
