// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package proposals

import (
	app "github.com/decred/politeia/app/v1"
	auth "github.com/decred/politeia/plugins/auth/v1"
)

// perms returns the user permissions for all plugin commands that are part
// of the proposals app.
func perms() []app.CmdPerm {
	return []app.CmdPerm{
		{
			Cmd: app.CmdDetails{
				PluginID: auth.PluginID,
				Version:  auth.PluginVersion,
				Name:     auth.CmdNewUser,
			},
			Levels: []string{
				auth.PermPublic,
			},
		},
	}
}
