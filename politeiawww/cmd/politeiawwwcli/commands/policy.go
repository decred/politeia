package commands

type PolicyCmd struct{}

func (cmd *PolicyCmd) Execute(args []string) error {
	_, err := Ctx.Policy()
	return err
}
