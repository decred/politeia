package commands

type VersionCmd struct{}

func (cmd *VersionCmd) Execute(args []string) error {
	vr, err := c.Version()
	if err != nil {
		return err
	}
	return Print(vr, cfg.Verbose, cfg.RawJSON)
}
