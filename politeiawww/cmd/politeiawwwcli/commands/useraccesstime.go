package commands

type UserAccessTimeCmd struct {
	Args struct {
		Token string `positional-arg-name:"token"`
	} `positional-args:"true" required:"true"`
}

func (cmd *UserAccessTimeCmd) Execute(args []string) error {
	// Get server's public key
	uatr, err := c.GetUserAccessTime(cmd.Args.Token)
	if err != nil {
		return err
	}
	return Print(uatr, cfg.Verbose, cfg.RawJSON)
}
