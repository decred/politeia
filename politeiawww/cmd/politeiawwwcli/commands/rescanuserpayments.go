package commands

import "github.com/decred/politeia/politeiawww/api/v1"

type RescanUserPaymentsCmd struct {
	Args struct {
		UserID string `positional-arg-name:"userid" description:"User ID"`
	} `positional-args:"true" required:"true"`
}

func (cmd *RescanUserPaymentsCmd) Execute(args []string) error {
	upr := &v1.UserPaymentsRescan{
		UserID: cmd.Args.UserID,
	}

	err := Print(upr, cfg.Verbose, cfg.RawJSON)
	if err != nil {
		return err
	}

	uprr, err := c.UserPaymentsRescan(upr)
	if err != nil {
		return err
	}

	return Print(uprr, cfg.Verbose, cfg.RawJSON)
}
