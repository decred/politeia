package commands

import (
	"github.com/decred/politeia/politeiawww/api/v1"
)

type EditUserCmd struct {
	ProposalEmailNotifications *uint64 `long:"proposalemailnotifications" optional:"true" description:"Whether to notify via email about proposals"`
}

func (cmd *EditUserCmd) Execute(args []string) error {
	// Setup request
	eu := &v1.EditUser{
		ProposalEmailNotifications: cmd.ProposalEmailNotifications,
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
