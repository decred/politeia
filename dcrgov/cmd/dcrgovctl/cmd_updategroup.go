// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"

	auth "github.com/decred/politeia/plugins/auth/v1"
	v1 "github.com/decred/politeia/server/api/v1"
)

// cmdLogin logs in a user. Session data is saved to disk by the http client
// and attached to subsequent commands.
type cmdUpdateGroup struct {
	Args struct {
		User   string `positional-arg-name:"user"`
		Action string `positional-arg-name:"action"`
		Group  string `positional-arg-name:"group"`
	} `required:"true" positional-args:"true"`
}

// Execute executes the command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdUpdateGroup) Execute(args []string) error {
	ug := auth.UpdateGroup{
		UserID: c.Args.User,
		Action: auth.ActionT(c.Args.Action),
		Group:  c.Args.Group,
	}
	payload, err := json.Marshal(ug)
	if err != nil {
		return err
	}
	cmd := v1.Cmd{
		Plugin:  auth.PluginID,
		Version: auth.Version,
		Name:    auth.CmdUpdateGroup,
		Payload: string(payload),
	}
	_, err = httpC.WriteCmd(cmd)
	if err != nil {
		return err
	}

	log.Infof("User group updated")

	return nil
}
