// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"

	auth "github.com/decred/politeia/plugins/auth/v1"
	v3 "github.com/decred/politeia/politeiawww/api/http/v3"
)

// cmdLogout logs out the user.
type cmdLogout struct{}

// Execute executes the command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdLogout) Execute(args []string) error {
	payload, err := json.Marshal(auth.Logout{})
	if err != nil {
		return err
	}
	cmd := v3.Cmd{
		Plugin:  auth.PluginID,
		Version: auth.Version,
		Name:    auth.CmdLogout,
		Payload: string(payload),
	}
	_, err = httpC.WriteCmd(cmd)
	if err != nil {
		return err
	}
	return nil
}
