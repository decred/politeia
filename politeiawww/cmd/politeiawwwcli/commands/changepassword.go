package commands

import (
	"fmt"
)

type ChangepasswordCmd struct {
	Args struct {
		Password    string `positional-arg-name:"currentPassword"`
		Newpassword string `positional-arg-name:"newPassword"`
	} `positional-args:"true" required:"true"`
}

func (cmd *ChangepasswordCmd) Execute(args []string) error {
	currPass := cmd.Args.Password
	newPass := cmd.Args.Newpassword

	cpr, err := Ctx.ChangePassword(currPass, newPass)
	if err != nil {
		return err
	}

	fmt.Printf("Response: %v", *cpr)
	return nil
}
