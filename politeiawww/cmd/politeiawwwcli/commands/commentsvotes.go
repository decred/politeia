package commands

type CommentsVotesCmd struct {
	Args struct {
		Token string `positional-arg-name:"token"`
	} `positional-args:"true" required:"true"`
}

func (cmd *CommentsVotesCmd) Execute(args []string) error {
	cvr, err := c.UserCommentsVotes(cmd.Args.Token)
	if err != nil {
		return err
	}
	return Print(cvr, cfg.Verbose, cfg.RawJSON)
}
