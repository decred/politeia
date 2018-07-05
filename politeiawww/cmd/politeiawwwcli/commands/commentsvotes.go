package commands

type CommentsvotesCmd struct {
	Args struct {
		Token string `positional-arg-name:"token"`
	} `positional-args:"true" required:"true"`
}

func (cmd *CommentsvotesCmd) Execute(args []string) error {
	_, err := Ctx.CommentsVotesGet(cmd.Args.Token)
	return err
}
