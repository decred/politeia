package commands

type LogoutCmd struct{}

func (cmd *LogoutCmd) Execute(args []string) error {
	lr, err := c.Logout()
	if err != nil {
		return err
	}
	return Print(lr, cfg.Verbose, cfg.RawJSON)
}
