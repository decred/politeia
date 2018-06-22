package commands

type ActivevotesCmd struct{}

func (cmd *ActivevotesCmd) Execute(args []string) error {
	_, err := Ctx.ActiveVotes()
	return err
}
