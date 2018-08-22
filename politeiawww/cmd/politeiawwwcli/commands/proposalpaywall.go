package commands

import "github.com/decred/politeia/politeiawww/api/v1"

type ProposalPaywallCmd struct{}

func (cmd *ProposalPaywallCmd) Execute(args []string) error {
	ppdr, err := c.ProposalPaywallDetails(&v1.ProposalPaywallDetails{})
	if err != nil {
		return err
	}
	return Print(ppdr, cfg.Verbose, cfg.RawJSON)
}
