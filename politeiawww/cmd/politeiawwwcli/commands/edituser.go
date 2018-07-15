package commands

type EdituserCmd struct {
	Args struct {
		UserID string `positional-arg-name:"userid"`
		Action int64  `positional-arg-name:"action"`
		Reason string `positional-arg-name:"reason"`
	} `positional-args:"true" required:"true"`
}

func (cmd *EdituserCmd) Execute(args []string) error {
	_, err := Ctx.EditUser(cmd.Args.UserID, cmd.Args.Action, cmd.Args.Reason)
	return err
}
