package commands

type ResetpasswordCmd struct {
	Args struct {
		Email       string `positional-arg-name:"email"`
		NewPassword string `positional-arg-name:"newpassword"`
	} `positional-args:"true" required:"true"`
}

func (cmd *ResetpasswordCmd) Execute(args []string) error {
	err := Ctx.ResetPassword(cmd.Args.Email, cmd.Args.NewPassword)
	return err
}
