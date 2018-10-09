package commands

type GetPaywallPaymentCmd struct{}

func (cmd *GetPaywallPaymentCmd) Execute(args []string) error {
	pppr, err := c.ProposalPaywallPayment()
	if err != nil {
		return err
	}
	return Print(pppr, cfg.Verbose, cfg.RawJSON)
}
