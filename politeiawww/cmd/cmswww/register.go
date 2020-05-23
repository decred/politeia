// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// RegisterUserCmd allows invited contractors to complete the registration
// process and will allow them to login and submit invoices to receive payment.
type RegisterUserCmd struct {
	Args struct {
		Email    string `positional-arg-name:"email"`
		Username string `positional-arg-name:"username"`
		Password string `positional-arg-name:"password"`
		Token    string `positional-arg-name:"token"`
	} `positional-args:"true" required:"true"`
}

// Execute executes the register user command
func (cmd *RegisterUserCmd) Execute(args []string) error {
	// Fetch  policy for password requirements
	pr, err := client.Policy()
	if err != nil {
		return fmt.Errorf("Policy: %v", err)
	}

	// Validate password
	if uint(len(cmd.Args.Password)) < pr.MinPasswordLength {
		return fmt.Errorf("password must be %v characters long",
			pr.MinPasswordLength)
	}

	// Create user identity and save it to disk
	id, err := shared.NewIdentity()
	if err != nil {
		return err
	}

	ru := &v1.RegisterUser{
		Email:             cmd.Args.Email,
		Username:          strings.TrimSpace(cmd.Args.Username),
		Password:          shared.DigestSHA3(cmd.Args.Password),
		VerificationToken: strings.TrimSpace(cmd.Args.Token),
		PublicKey:         hex.EncodeToString(id.Public.Key[:]),
	}

	// Print request details
	err = shared.PrintJSON(ru)
	if err != nil {
		return err
	}

	// Send request
	rur, err := client.RegisterUser(ru)
	if err != nil {
		return fmt.Errorf("Register: %v", err)
	}

	err = cfg.SaveIdentity(ru.Username, id)
	if err != nil {
		return err
	}

	// Print response details
	err = shared.PrintJSON(rur)
	if err != nil {
		return err
	}

	// Login to cms
	l := &www.Login{
		Email:    cmd.Args.Email,
		Password: shared.DigestSHA3(cmd.Args.Password),
	}

	_, err = client.Login(l)
	if err != nil {
		return err
	}

	// Update the logged in username that we store
	// on disk to know what identity to load.
	return cfg.SaveLoggedInUsername(ru.Username)
}
