package commands

type GetcommentsCmd struct {
	Args struct {
		Token string `positional-arg-name:"token"`
	} `positional-args:"true" required:"true"`
}

func (cmd *GetcommentsCmd) Execute(args []string) error {
	_, err := Ctx.CommentGet(cmd.Args.Token)
	return err
}
