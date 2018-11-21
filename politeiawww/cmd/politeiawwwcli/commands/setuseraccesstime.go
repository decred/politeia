package commands

import (
	"github.com/decred/politeia/politeiawww/api/v1"
)

type SetUserAccessTimeCmd struct {
	Args struct {
		Token      string `positional-arg-name:"token"`
		AccessTime int64  `positional-arg-name:"accesstime"`
	} `positional-args:"true" required:"true"`
}

func (cmd *SetUserAccessTimeCmd) Execute(args []string) error {
	var uat v1.SetUserAccessTime
	uat.Token = cmd.Args.Token
	uat.AccessTime = cmd.Args.AccessTime

	// Print request details
	err := Print(uat, cfg.Verbose, cfg.RawJSON)
	if err != nil {
		return err
	}

	ur, err := c.SetUserAccesstime(uat)
	if err != nil {
		return err
	}
	return Print(ur, cfg.Verbose, cfg.RawJSON)
}
