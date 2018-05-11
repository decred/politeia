package commands

type MeCmd struct{}

func (cmd *MeCmd) Execute(args []string) error {
	_, err := Ctx.Me()
	return err
}
