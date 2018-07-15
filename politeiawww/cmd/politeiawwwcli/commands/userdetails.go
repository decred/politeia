package commands

type UserdetailsCmd struct {
	Args struct {
		UserID string `positional-arg-name:"userid"`
	} `positional-args:"true" required:"true"`
}

func (cmd *UserdetailsCmd) Execute(args []string) error {
	_, err := Ctx.GetUserDetails(cmd.Args.UserID)
	return err
}
