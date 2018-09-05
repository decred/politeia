package commands

import "fmt"

type ResetpasswordCmd struct {
	Args struct {
		Email       string `positional-arg-name:"email"`
		NewPassword string `positional-arg-name:"newpassword"`
	} `positional-args:"true" required:"true"`
}

func (cmd *ResetpasswordCmd) Execute(args []string) error {
	email := cmd.Args.Email
	newPassword := cmd.Args.NewPassword

	// Fetch Politeia password requirements.
	pr, err := Ctx.Policy()
	if err != nil {
		return err
	}

	// Validate new password.
	if uint(len(newPassword)) < pr.MinPasswordLength {
		return fmt.Errorf("password must be %v characters long",
			pr.MinPasswordLength)
	}

	return Ctx.ResetPassword(email, newPassword)
}
