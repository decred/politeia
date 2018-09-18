package commands

import (
	"fmt"

	"github.com/decred/politeia/politeiawww/api/v1"
)

type UserProposalsCmd struct {
	Args struct {
		UserID string `positional-arg-name:"userID"`
	} `positional-args:"true" required:"true"`
}

func (cmd *UserProposalsCmd) Execute(args []string) error {
	// Get server public key
	vr, err := c.Version()
	if err != nil {
		return err
	}

	// Get user proposals
	upr, err := c.UserProposals(&v1.UserProposals{
		UserId: cmd.Args.UserID,
	})
	if err != nil {
		return err
	}

	// Verify proposal censorship records
	for _, p := range upr.Proposals {
		err := VerifyProposal(p, vr.PubKey)
		if err != nil {
			return fmt.Errorf("unable to verify proposal %v: %v",
				p.CensorshipRecord.Token, err)
		}
	}

	// Print user proposals
	return Print(upr, cfg.Verbose, cfg.RawJSON)
}
