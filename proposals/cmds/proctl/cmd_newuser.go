// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"encoding/json"

	auth "github.com/decred/politeia/plugins/auth/v1"
	v3 "github.com/decred/politeia/politeiawww/api/http/v3"
	"golang.org/x/crypto/sha3"
)

// cmdNewUser creates a new user.
type cmdNewUser struct {
	Args struct {
		Username string `positional-arg-name:"username" required:"true"`
		Password string `positional-arg-name:"password" required:"true"`
		Email    string `positional-arg-name:"email" optional:"true"`
	} `positional-args:"true"`
}

// Execute executes the command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdNewUser) Execute(args []string) error {
	var (
		username = c.Args.Username
		password = c.Args.Password
		email    = c.Args.Email
	)

	var ci *auth.NewContactInfo
	if email != "" {
		ci = &auth.NewContactInfo{
			Type:    auth.ContactTypeEmail,
			Contact: email,
		}
	}
	nu := auth.NewUser{
		Username: username,
		// The password is hashed client side so that
		// it doesn't travel clear text. This is how
		// politeiagui submits passwords.
		Password:    hexSHA3(password),
		ContactInfo: ci,
	}
	b, err := json.Marshal(nu)
	if err != nil {
		return err
	}
	cmd := v3.Cmd{
		Plugin:  auth.PluginID,
		Version: auth.Version,
		Name:    auth.CmdNewUser,
		Payload: string(b),
	}
	_, err = httpC.WriteCmd(cmd)
	if err != nil {
		return err
	}

	log.Infof("New user '%v' created", username)

	return nil
}

// hexSHA3 returns the hex encoded SHA3-256 digest for a string.
func hexSHA3(s string) string {
	h := sha3.New256()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}
