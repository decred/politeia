package commands

type ChangeusernameCmd struct {
	Args struct {
		Password    string `positional-arg-name:"password"`
		Newusername string `positional-arg-name:"newusername"`
	} `positional-args:"true" required:"true"`
}

func (cmd *ChangeusernameCmd) Execute(args []string) error {
	password := cmd.Args.Password
	newUsername := cmd.Args.Newusername

	_, err := Ctx.ChangeUsername(password, newUsername)
	return err
}
