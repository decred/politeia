package commands

type PolicyCmd struct{}

func (cmd *PolicyCmd) Execute(args []string) error {
	pr, err := c.Policy()
	if err != nil {
		return err
	}
	return Print(pr, cfg.Verbose, cfg.RawJSON)
}
