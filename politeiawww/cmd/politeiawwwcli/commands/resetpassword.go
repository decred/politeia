package commands

type ResetpasswordCmd struct {
	Args struct {
		Email       string `positional-arg-name:"email"`
		Password    string `positional-arg-name:"password"`
		NewPassword string `positional-arg-name:"newpassword"`
	} `positional-args:"true" required:"true"`
}

func (cmd *ResetpasswordCmd) Execute(args []string) error {
	err := Ctx.ResetPassword(cmd.Args.Email, cmd.Args.Password,
		cmd.Args.NewPassword)
	return err
}
