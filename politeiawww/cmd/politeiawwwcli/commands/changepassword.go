package commands

type ChangepasswordCmd struct {
	Args struct {
		Password    string `positional-arg-name:"currentPassword"`
		Newpassword string `positional-arg-name:"newPassword"`
	} `positional-args:"true" required:"true"`
}

func (cmd *ChangepasswordCmd) Execute(args []string) error {
	currPass := cmd.Args.Password
	newPass := cmd.Args.Newpassword

	_, err := Ctx.ChangePassword(currPass, newPass)
	return err
}
