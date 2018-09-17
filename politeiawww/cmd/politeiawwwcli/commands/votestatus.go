package commands

type VoteStatusCmd struct {
	Args struct {
		Token string `positional-arg-name:"token" description:"Proposal censorship token"`
	} `positional-args:"true" required:"true"`
}

func (cmd *VoteStatusCmd) Execute(args []string) error {
	_, err := Ctx.VoteStatus(cmd.Args.Token)
	return err
}
