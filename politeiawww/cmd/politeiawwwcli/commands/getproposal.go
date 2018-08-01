package commands

type GetproposalCmd struct {
	Args struct {
		Token string `positional-arg-name:"token"`
	} `positional-args:"true" required:"true"`
}

func (cmd *GetproposalCmd) Execute(args []string) error {
	v, err := Ctx.Version()
	if err != nil {
		return err
	}
	_, err = Ctx.GetProp(cmd.Args.Token, v.PubKey)
	return err
}
