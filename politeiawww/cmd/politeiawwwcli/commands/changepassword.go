package commands

import "fmt"

type ChangepasswordCmd struct {
	Args struct {
		Password    string `positional-arg-name:"currentPassword"`
		Newpassword string `positional-arg-name:"newPassword"`
	} `positional-args:"true" required:"true"`
}

func (cmd *ChangepasswordCmd) Execute(args []string) error {
	currPass := cmd.Args.Password
	newPass := cmd.Args.Newpassword

	// Fetch Politeia password requirements.
	pr, err := Ctx.Policy()
	if err != nil {
		return err
	}

	// Validate new password.
	if uint(len(newPass)) < pr.MinPasswordLength {
		return fmt.Errorf("password must be %v characters long",
			pr.MinPasswordLength)
	}

	_, err = Ctx.ChangePassword(currPass, newPass)
	return err
}
