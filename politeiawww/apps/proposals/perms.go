// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package proposals

import (
	plugin "github.com/decred/politeia/politeiawww/plugin/v1"
	auth "github.com/decred/politeia/politeiawww/plugins/auth/v1"
)

// perms returns the user permissions for all plugin commands that are part
// of the proposals app.
func perms() []plugin.CmdPerm {
	return []plugin.CmdPerm{
		{
			PluginID: auth.PluginID,
			Cmd:      auth.CmdNewUser,
			Perm:     auth.PermPublic,
		},
	}
}
