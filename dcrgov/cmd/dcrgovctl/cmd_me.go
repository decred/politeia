// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"

	auth "github.com/decred/politeia/plugins/auth/v1"
	v1 "github.com/decred/politeia/server/api/v1"
)

// cmdMe returns information about the logged in user.
type cmdMe struct{}

// Execute executes the command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdMe) Execute(args []string) error {
	payload, err := json.Marshal(auth.Me{})
	if err != nil {
		return err
	}
	cmd := v1.Cmd{
		Plugin:  auth.PluginID,
		Version: auth.Version,
		Name:    auth.CmdMe,
		Payload: string(payload),
	}
	r, err := httpC.ReadCmd(cmd)
	if err != nil {
		return err
	}
	var mr auth.MeReply
	err = json.Unmarshal([]byte(r.Payload), &mr)
	if err != nil {
		return err
	}

	log.Infof("%v", formatJSON(mr))

	return nil
}
