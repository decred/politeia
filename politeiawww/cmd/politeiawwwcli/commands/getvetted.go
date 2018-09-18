package commands

import (
	"fmt"

	"github.com/decred/politeia/politeiawww/api/v1"
)

type GetVettedCmd struct {
	Before string `long:"before" optional:"true" description:"A proposal censorship token; if provided, the page of proposals returned will end right before the proposal whose token is provided."`
	After  string `long:"after" optional:"true" description:"A proposal censorship token; if provided, the page of proposals returned will end right after the proposal whose token is provided."`
}

func (cmd *GetVettedCmd) Execute(args []string) error {
	if cmd.Before != "" && cmd.After != "" {
		return fmt.Errorf(ErrorBeforeAndAfter)
	}

	// Get server's public key
	vr, err := c.Version()
	if err != nil {
		return err
	}

	// Get all vetted proposals
	gavr, err := c.GetAllVetted(&v1.GetAllVetted{
		Before: cmd.Before,
		After:  cmd.After,
	})
	if err != nil {
		return err
	}

	// Verify proposal censorship records
	for _, p := range gavr.Proposals {
		err = VerifyProposal(p, vr.PubKey)
		if err != nil {
			return fmt.Errorf("unable to verify proposal %v: %v",
				p.CensorshipRecord.Token, err)
		}
	}

	// Print vetted proposals
	return Print(gavr, cfg.Verbose, cfg.RawJSON)
}
