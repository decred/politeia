package commands

import "github.com/decred/politeia/politeiawww/api/v1"

type UsernamesByIDCmd struct {
	Args struct {
		UserIDs []string `positional-arg-name:"userIDs"`
	} `positional-args:"true" required:"true"`
}

func (cmd *UsernamesByIDCmd) Execute(args []string) error {
	ubi := &v1.UsernamesById{
		UserIds: cmd.Args.UserIDs,
	}

	// Print request details
	err := Print(ubi, cfg.Verbose, cfg.RawJSON)
	if err != nil {
		return err
	}

	// Send request
	ubir, err := c.UsernamesByID(ubi)
	if err != nil {
		return err
	}

	// Print response details
	return Print(ubir, cfg.Verbose, cfg.RawJSON)
}
