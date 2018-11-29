package commands

import (
	"fmt"

	"github.com/decred/politeia/politeiawww/api/v1"
)

type GetProposalCmd struct {
	Args struct {
		Token   string `positional-arg-name:"token" required:"true"`
		Version string `positional-arg-name:"version"`
	} `positional-args:"true"`
}

func (cmd *GetProposalCmd) Execute(args []string) error {
	// Get server's public key
	vr, err := c.Version()
	if err != nil {
		return err
	}

	// Get proposal
	pdr, err := c.ProposalDetails(cmd.Args.Token, &v1.ProposalsDetails{
		Version: cmd.Args.Version,
	})
	if err != nil {
		return err
	}

	// Verify proposal censorship record
	err = VerifyProposal(pdr.Proposal, vr.PubKey)
	if err != nil {
		return fmt.Errorf("unable to verify proposal %v: %v",
			pdr.Proposal.CensorshipRecord.Token, err)
	}

	// Print proposal details
	return Print(pdr, cfg.Verbose, cfg.RawJSON)
}
