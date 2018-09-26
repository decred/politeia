package commands

type GetCommentsCmd struct {
	Args struct {
		Token string `positional-arg-name:"token"`
	} `positional-args:"true" required:"true"`
}

func (cmd *GetCommentsCmd) Execute(args []string) error {
	gcr, err := c.GetComments(cmd.Args.Token)
	if err != nil {
		return err
	}
	return Print(gcr, cfg.Verbose, cfg.RawJSON)
}
