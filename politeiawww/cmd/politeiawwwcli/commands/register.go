// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"golang.org/x/crypto/ssh/terminal"
)

// RegisterUserCmd allows invited contractors to complete the registration
// process and will allow them to login and submit invoices to receive payment.
type RegisterUserCmd struct {
	Args struct {
		Email string `positional-arg-name:"email"`
		Token string `positional-arg-name:"token"`
	} `positional-args:"true" required:"true"`
	Username string `long:"username" optional:"true" description:"Username"`
	Password string `long:"password" optional:"true" description:"Password"`
}

// Execute executes the register user command
func (cmd *RegisterUserCmd) Execute(args []string) error {
	email := cmd.Args.Email
	token := cmd.Args.Token

	if email == "" || token == "" {
		return fmt.Errorf("invalid credentials: you must either specify both " +
			"email and token to register an account with CMS")
	}

	// Fetch CSRF tokens
	_, err := client.Version()
	if err != nil {
		return fmt.Errorf("Version: %v", err)
	}

	// Fetch  policy for password requirements
	pr, err := client.Policy()
	if err != nil {
		return fmt.Errorf("Policy: %v", err)
	}

	if cmd.Username == "" || cmd.Password == "" {
		reader := bufio.NewReader(os.Stdin)
		if cmd.Username == "" {
			fmt.Print("Create a username: ")
			cmd.Username, _ = reader.ReadString('\n')
		}
		for {
			prompt := "Enter a password: "
			for {
				fmt.Print(prompt)
				pass, err := terminal.ReadPassword(int(os.Stdin.Fd()))
				if err != nil {
					return err
				}
				fmt.Print("\n")
				pass = bytes.TrimSpace(pass)
				if len(pass) == 0 {
					continue
				}
				cmd.Password = string(pass)
				break
			}
			prompt = "Confirm password: "
			verifyPass := ""
			for {
				fmt.Print(prompt)
				pass, err := terminal.ReadPassword(int(os.Stdin.Fd()))
				if err != nil {
					return err
				}
				fmt.Print("\n")
				pass = bytes.TrimSpace(pass)
				if len(pass) == 0 {
					continue
				}
				verifyPass = string(pass)
				break
			}
			if verifyPass != cmd.Password {
				cmd.Password = ""
				fmt.Println("Passwords do not match, please try again.")
				continue
			} else {
				break
			}
		}
	}

	// Validate password
	if uint(len(cmd.Password)) < pr.MinPasswordLength {
		return fmt.Errorf("password must be %v characters long",
			pr.MinPasswordLength)
	}

	// Create user identity and save it to disk
	id, err := newIdentity()
	if err != nil {
		return err
	}

	ru := &v1.RegisterUser{
		Email:             email,
		Username:          strings.TrimSpace(cmd.Username),
		Password:          digestSHA3(cmd.Password),
		VerificationToken: strings.TrimSpace(cmd.Args.Token),
		PublicKey:         hex.EncodeToString(id.Public.Key[:]),
	}

	// Print request details
	err = printJSON(ru)
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
	err = printJSON(rur)
	if err != nil {
		return err
	}

	// Login to cms
	l := &www.Login{
		Username: cmd.Username,
		Password: digestSHA3(cmd.Password),
	}

	_, err = client.Login(l)
	if err != nil {
		return err
	}

	// Update the logged in username that we store
	// on disk to know what identity to load.
	return cfg.SaveLoggedInUsername(ru.Username)
}
