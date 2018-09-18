package commands

type SecretCmd struct{}

func (cmd *SecretCmd) Execute(args []string) error {
	ue, err := c.Secret()
	if err != nil {
		return err
	}
	return Print(ue, cfg.Verbose, cfg.RawJSON)
}
