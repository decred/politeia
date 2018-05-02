package commands

type UserproposalsCmd struct {
	Args struct {
		UserId string `positional-arg-name:"userid"`
	} `positional-args:"true" required:"true"`
}

func (cmd *UserproposalsCmd) Execute(args []string) error {
	_, err := Ctx.ProposalsForUser(cmd.Args.UserId)
	return err
}
