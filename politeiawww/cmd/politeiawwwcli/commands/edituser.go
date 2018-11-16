package commands

import (
	"github.com/decred/politeia/politeiawww/api/v1"
)

type EditUserCmd struct {
	EmailNotifications *uint64 `long:"emailnotifications" optional:"true" description:"Whether to notify via emails"`
}

func (cmd *EditUserCmd) Execute(args []string) error {
	// Setup request
	eu := &v1.EditUser{
		EmailNotifications: cmd.EmailNotifications,
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
