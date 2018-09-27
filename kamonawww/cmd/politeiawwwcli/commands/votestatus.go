package commands

type VoteStatusCmd struct {
	Args struct {
		Token string `positional-arg-name:"token" description:"Proposal censorship token"`
	} `positional-args:"true" required:"true"`
}

func (cmd *VoteStatusCmd) Execute(args []string) error {
	vsr, err := c.VoteStatus(cmd.Args.Token)
	if err != nil {
		return err
	}
	return Print(vsr, cfg.Verbose, cfg.RawJSON)
}
