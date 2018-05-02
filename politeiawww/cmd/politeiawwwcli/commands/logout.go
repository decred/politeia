package commands

type LogoutCmd struct{}

func (cmd *LogoutCmd) Execute(args []string) error {
	err := Ctx.Logout()
	return err
}
