// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package proposals

import (
	"github.com/decred/politeia/app"
	v1 "github.com/decred/politeia/plugins/auth/v1"
)

// perms returns the user permissions for all plugin commands that are part
// of the proposals app.
func perms() []app.CmdPerms {
	return []app.CmdPerms{
		{
			Cmd: app.CmdDetails{
				Plugin:  v1.ID,
				Version: v1.Version,
				Cmd:     v1.CmdNewUser,
			},
			Perms: []string{v1.PermPublic},
		},
	}
}
