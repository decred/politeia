package commands

import (
	"fmt"

	"github.com/decred/politeia/politeiawww/api/v1"
)

type ResetPasswordCmd struct {
	Args struct {
		Email       string `positional-arg-name:"email"`
		NewPassword string `positional-arg-name:"newpassword"`
	} `positional-args:"true" required:"true"`
}

func (cmd *ResetPasswordCmd) Execute(args []string) error {
	email := cmd.Args.Email
	newPassword := cmd.Args.NewPassword

	// Get password requirements
	pr, err := c.Policy()
	if err != nil {
		return err
	}

	// Validate new password
	if uint(len(newPassword)) < pr.MinPasswordLength {
		return fmt.Errorf("password must be %v characters long",
			pr.MinPasswordLength)
	}

	// The reset password command is special.  It must be called twice with
	// different parameters.  For the 1st call, it should be called with only
	// an email parameter. On success it will send an email containing a
	// verification token to the email address provided.  If the email server
	// has been disabled, the verification token is sent back in the response
	// body. The 2nd call to reset password should be called with an email,
	// verification token, and new password parameters.
	//
	// politeiawwwcli assumes the email server is disabled.

	// 1st reset password call
	rp := &v1.ResetPassword{
		Email:       email,
		NewPassword: DigestSHA3(newPassword),
	}

	err = Print(rp, cfg.Verbose, cfg.RawJSON)
	if err != nil {
		return err
	}

	rpr, err := c.ResetPassword(rp)
	if err != nil {
		return err
	}

	err = Print(rpr, cfg.Verbose, cfg.RawJSON)
	if err != nil {
		return err
	}

	// 2nd reset password call
	rp = &v1.ResetPassword{
		Email:             email,
		NewPassword:       DigestSHA3(newPassword),
		VerificationToken: rpr.VerificationToken,
	}

	err = Print(rp, cfg.Verbose, cfg.RawJSON)
	if err != nil {
		return err
	}

	rpr, err = c.ResetPassword(rp)
	if err != nil {
		return err
	}

	return Print(rpr, cfg.Verbose, cfg.RawJSON)
}
