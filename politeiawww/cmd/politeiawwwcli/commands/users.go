package commands

type UsersCmd struct {
	Email    string `long:"email" optional:"true" description:"Email query"`
	Username string `long:"username" optional:"true" description:"Username query"`
}

func (cmd *UsersCmd) Execute(args []string) error {
	ur, err := c.Users(cmd.Email, cmd.Username)
	if err != nil {
		return err
	}
	return Print(ur, cfg.Verbose, cfg.RawJSON)
}
