// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package proposals

import (
	auth "github.com/decred/politeia/plugins/auth/v1"
	app "github.com/decred/politeia/politeiawww/app/v1"
)

// perms returns the user permissions for all plugin commands that are part
// of the proposals app.
func perms() []app.CmdPerm {
	return []app.CmdPerm{
		{
			PluginID: auth.PluginID,
			Cmd:      auth.CmdNewUser,
			Perm: []string{
				auth.PermPublic,
			},
		},
	}
}
