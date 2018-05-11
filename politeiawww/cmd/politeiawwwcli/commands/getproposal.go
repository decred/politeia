package commands

type GetproposalCmd struct {
	Args struct {
		Token string `positional-arg-name:"token"`
	} `positional-args:"true" required:"true"`
}

func (cmd *GetproposalCmd) Execute(args []string) error {
	_, err := Ctx.GetProp(cmd.Args.Token)
	return err
}
