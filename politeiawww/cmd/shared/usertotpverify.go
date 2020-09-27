// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package shared

import (
	"fmt"

	v1 "github.com/decred/politeia/politeiawww/api/www/v1"
)

// UserTOTPVerifyCmd sets the TOTP key for the logged in user.
type UserTOTPVerifyCmd struct {
	Args struct {
		Code string `positional-arg-name:"code"`
	} `positional-args:"true"`
}

// Execute executes the set totp command.
func (cmd *UserTOTPVerifyCmd) Execute(args []string) error {
	// Setup new user request
	st := &v1.VerifyTOTP{
		Code: cmd.Args.Code,
	}

	// Print request details
	err := PrintJSON(st)
	if err != nil {
		return err
	}

	// Send request
	str, err := client.VerifyTOTP(st)
	if err != nil {
		return fmt.Errorf("VerifyTOTP: %v", err)
	}

	// Print response details
	err = PrintJSON(str)
	if err != nil {
		return err
	}

	return nil
}
