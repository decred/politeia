package commands

type ProposalVotesCmd struct {
	Args struct {
		Token string `positional-arg-name:"token" description:"Proposal censorship token"`
	} `positional-args:"true" required:"true"`
}

func (cmd *ProposalVotesCmd) Execute(args []string) error {
	vrr, err := c.ProposalVotes(cmd.Args.Token)
	if err != nil {
		return err
	}
	return Print(vrr, cfg.Verbose, cfg.RawJSON)
}
