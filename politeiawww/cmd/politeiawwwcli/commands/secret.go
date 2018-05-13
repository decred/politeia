package commands

type SecretCmd struct{}

func (cmd *SecretCmd) Execute(args []string) error {
	err := Ctx.Secret()
	return err
}
