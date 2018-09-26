package commands

import (
	"fmt"

	"github.com/decred/politeia/politeiawww/api/v1"
)

type GetUnvettedCmd struct {
	Before string `long:"before" optional:"true" description:"A proposal censorship token; if provided, the page of proposals returned will end right before the proposal whose token is provided."`
	After  string `long:"after" optional:"true" description:"A proposal censorship token; if provided, the page of proposals returned will begin right after the proposal whose token is provided."`
}

func (cmd *GetUnvettedCmd) Execute(args []string) error {
	if cmd.Before != "" && cmd.After != "" {
		return fmt.Errorf(ErrorBeforeAndAfter)
	}

	// Get server's public key
	vr, err := c.Version()
	if err != nil {
		return err
	}

	// Get all unvetted proposals
	gaur, err := c.GetAllUnvetted(&v1.GetAllUnvetted{
		Before: cmd.Before,
		After:  cmd.After,
	})
	if err != nil {
		return err
	}

	// Verify proposal censorship records
	for _, p := range gaur.Proposals {
		err = VerifyProposal(p, vr.PubKey)
		if err != nil {
			return fmt.Errorf("unable to verify proposal %v: %v",
				p.CensorshipRecord.Token, err)
		}
	}

	// Print unvetted proposals
	return Print(gaur, cfg.Verbose, cfg.RawJSON)
}
