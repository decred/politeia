package commands

type UsernamesbyidCmd struct {
	Args struct {
		UserIds []string `positional-arg-name:"userids"`
	} `positional-args:"true" required:"true"`
}

func (cmd *UsernamesbyidCmd) Execute(args []string) error {
	userIds := cmd.Args.UserIds
	_, err := Ctx.UsernamesById(userIds)
	return err
}
