// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"

	auth "github.com/decred/politeia/plugins/auth/v1"
	v1 "github.com/decred/politeia/plugins/auth/v1"
	v3 "github.com/decred/politeia/politeiawww/api/http/v3"
)

// cmdLogin logs in a user. Session data is saved to disk by the http client
// and attached to subsequent commands.
type cmdLogin struct {
	Args struct {
		Username string `positional-arg-name:"username" required:"true"`
		Password string `positional-arg-name:"password" required:"true"`
	} `positional-args:"true"`
}

// Execute executes the command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdLogin) Execute(args []string) error {
	var (
		username = c.Args.Username
		password = c.Args.Password
	)

	l := auth.Login{
		Username: username,
		// The password is hashed client side so that
		// it doesn't travel clear text. This is how
		// politeiagui submits passwords.
		Password: hexSHA3(password),
	}
	payload, err := json.Marshal(l)
	if err != nil {
		return err
	}
	cmd := v3.Cmd{
		Plugin:  auth.PluginID,
		Version: auth.Version,
		Name:    auth.CmdLogin,
		Payload: string(payload),
	}
	r, err := httpC.WriteCmd(cmd)
	if err != nil {
		return err
	}
	var lr v1.LoginReply
	err = json.Unmarshal([]byte(r.Payload), &lr)
	if err != nil {
		return err
	}

	log.Infof("Logged in %v", username)
	log.Infof("%v", formatJSON(lr))

	return nil
}
