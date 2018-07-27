package commands

type ProposalpaywallCmd struct{}

func (cmd *ProposalpaywallCmd) Execute(args []string) error {
	_, err := Ctx.ProposalPaywall()
	return err
}
