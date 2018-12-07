package commands

import (
	"fmt"

	"github.com/decred/politeia/politeiawww/api/v1"
)

// Help message displayed for the command 'politeiawwwcli help changepassword'
var ChangePasswordCmdHelpMsg = `changepassword "currentPassword" "newPassword" 

Change password for the currently logged in user. 

Arguments:
1. currentPassword   (string, required)   Current password 
2. newPassword       (string, required)   New password  

Result:
{
  "currentpassword":   (string)  Current password 
  "newpassword":       (string)  New password 
}
{}`

type ChangePasswordCmd struct {
	Args struct {
		Password    string `positional-arg-name:"currentPassword"`
		NewPassword string `positional-arg-name:"newPassword"`
	} `positional-args:"true" required:"true"`
}

func (cmd *ChangePasswordCmd) Execute(args []string) error {
	// Get password requirements
	pr, err := c.Policy()
	if err != nil {
		return err
	}

	// Validate new password
	if uint(len(cmd.Args.NewPassword)) < pr.MinPasswordLength {
		return fmt.Errorf("password must be %v characters long",
			pr.MinPasswordLength)
	}

	// Setup change password request
	cp := &v1.ChangePassword{
		CurrentPassword: DigestSHA3(cmd.Args.Password),
		NewPassword:     DigestSHA3(cmd.Args.NewPassword),
	}

	// Print request details
	err = Print(cp, cfg.Verbose, cfg.RawJSON)
	if err != nil {
		return err
	}

	// Send request
	cpr, err := c.ChangePassword(cp)
	if err != nil {
		return err
	}

	// Print response details
	return Print(cpr, cfg.Verbose, cfg.RawJSON)
}
