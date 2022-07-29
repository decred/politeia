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
		authPerms(),
	}
}

// authPerms returns the CmdDetails for all of the auth plugin commands that
// are part of the app.
func authPerms() []app.CmdDetails {
	// This is an abbreviated way of populating
	// the CmdDetails list since the PluginID
	// and Version will be the same for all of
	// the commands.
	var c = []struct {
		Name   string
		Groups []string
	}{
		{
			Name:   auth.CmdNewUser,
			Groups: []string{auth.PublicUser},
		},
		{
			Name:   auth.CmdLogin,
			Groups: []string{auth.PublicUser},
		},
		{
			Name:   auth.CmdLogout,
			Groups: []string{auth.StandardUser},
		},
		{
			Name:   auth.CmdMe,
			Groups: []string{auth.PublicUser},
		},
	}

	cmds := make([]app.CmdDetails, 0, len(c))
	for _, v := range c {
		cmds = append(cmds, app.Details{
			Plugin:  auth.PluginID,
			Version: auth.Version,
			Name:    v.Name,
			Groups:  v.Groups,
		})
	}

	return cmds
}
