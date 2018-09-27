package commands

type UserDetailsCmd struct {
	Args struct {
		UserID string `positional-arg-name:"userid"`
	} `positional-args:"true" required:"true"`
}

func (cmd *UserDetailsCmd) Execute(args []string) error {
	udr, err := c.UserDetails(cmd.Args.UserID)
	if err != nil {
		return err
	}
	return Print(udr, cfg.Verbose, cfg.RawJSON)
}
