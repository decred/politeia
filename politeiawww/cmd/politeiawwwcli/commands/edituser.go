package commands

import (
	"github.com/decred/politeia/politeiawww/api/v1"
)

type EditUserCmd struct {
	MyProposalNotifications      *uint64 `long:"myproposalnotifications" optional:"true" description:"Whether to notify via email about my proposals"`
	RegularProposalNotifications *uint64 `long:"regularproposalnotifications" optional:"true" description:"Whether to notify via email about others' proposals"`
	AdminProposalNotifications   *uint64 `long:"adminproposalnotifications" optional:"true" description:"Whether to notify via email about proposals that require admin attention"`
}

func (cmd *EditUserCmd) Execute(args []string) error {
	// Setup request
	eu := &v1.EditUser{
		MyProposalNotifications:      cmd.MyProposalNotifications,
		RegularProposalNotifications: cmd.RegularProposalNotifications,
		AdminProposalNotifications:   cmd.AdminProposalNotifications,
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
