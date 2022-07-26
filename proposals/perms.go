// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package proposals

import (
	"github.com/decred/politeia/app"
	auth "github.com/decred/politeia/plugins/auth/v1"
)

// perms returns the user permissions for all plugin commands that are part
// of the proposals app.
func perms() []app.CmdPerms {
	return []app.CmdPerms{
		{
			Cmd: app.CmdDetails{
				Plugin:  auth.PluginID,
				Version: auth.Version,
				Name:    auth.CmdNewUser,
			},
			Groups: []string{auth.PublicUser},
		},
	}
}
