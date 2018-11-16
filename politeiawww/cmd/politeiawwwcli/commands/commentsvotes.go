package commands

type CommentsLikesCmd struct {
	Args struct {
		Token string `positional-arg-name:"token"`
	} `positional-args:"true" required:"true"`
}

func (cmd *CommentsLikesCmd) Execute(args []string) error {
	cvr, err := c.UserCommentsLikes(cmd.Args.Token)
	if err != nil {
		return err
	}
	return Print(cvr, cfg.Verbose, cfg.RawJSON)
}
