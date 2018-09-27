package commands

type MeCmd struct{}

func (cmd *MeCmd) Execute(args []string) error {
	lr, err := c.Me()
	if err != nil {
		return err
	}
	return Print(lr, cfg.Verbose, cfg.RawJSON)
}
