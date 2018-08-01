package commands

type UserproposalsCmd struct {
	Args struct {
		UserId string `positional-arg-name:"userid"`
	} `positional-args:"true" required:"true"`
}

func (cmd *UserproposalsCmd) Execute(args []string) error {
	v, err := Ctx.Version()
	if err != nil {
		return err
	}
	_, err = Ctx.ProposalsForUser(cmd.Args.UserId, v.PubKey)
	return err
}
