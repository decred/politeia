package commands

import "github.com/decred/politeia/politeiawww/api/v1"

type EditUserCmd struct {
	Args struct {
		UserID string `positional-arg-name:"userid"`
		Action int64  `positional-arg-name:"action"`
		Reason string `positional-arg-name:"reason"`
	} `positional-args:"true" required:"true"`
}

func (cmd *EditUserCmd) Execute(args []string) error {
	eu := &v1.EditUser{
		UserID: cmd.Args.UserID,
		Action: v1.UserEditActionT(cmd.Args.Action),
		Reason: cmd.Args.Reason,
	}

	// Print request details
	err := Print(eu, cfg.Verbose, cfg.RawJSON)
	if err != nil {
		return err
	}

	// Send request
	eur, err := c.EditUser(eu)
	if err != nil {
		return err
	}

	// Print response details
	return Print(eur, cfg.Verbose, cfg.RawJSON)
}
