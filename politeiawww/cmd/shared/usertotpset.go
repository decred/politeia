// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package shared

import (
	"fmt"

	v1 "github.com/decred/politeia/politeiawww/api/www/v1"
)

// UserTOTPSetCmd sets the TOTP key for the logged in user.
type UserTOTPSetCmd struct {
	Args struct {
		Code string `positional-arg-name:"code"`
	} `positional-args:"true"`
}

// Execute executes the set totp command.
func (cmd *UserTOTPSetCmd) Execute(args []string) error {
	// Setup new user request
	st := &v1.SetTOTP{
		Code: cmd.Args.Code,
		Type: 1,
	}

	// Print request details
	err := PrintJSON(st)
	if err != nil {
		return err
	}

	// Send request
	str, err := client.SetTOTP(st)
	if err != nil {
		return fmt.Errorf("SetTOTP: %v", err)
	}

	// Print response details
	err = PrintJSON(str)
	if err != nil {
		return err
	}

	return nil
}
