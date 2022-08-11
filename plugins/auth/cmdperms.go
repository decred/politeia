// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package auth

import "github.com/decred/politeia/app"

// SetCmdPerms sets the permissions for a list of plugin commands.
func (p *authp) SetCmdPerms(perms []app.CmdPerms) {
	for _, v := range perms {
		p.setPerm(v)
	}
}

// setPerm sets a permission level for a command.
func (p *authp) setPerm(cp app.CmdPerms) {
	c := cp.Cmd.String()
	userGroups, ok := p.perms[c]
	if !ok {
		userGroups = make(map[string]struct{}, 64)
	}
	for _, v := range cp.Groups {
		userGroups[v] = struct{}{}
	}
	p.perms[c] = userGroups
}

// cmdIsAllowed returns whether the execution of a command is allowed for a
// permission level.
func (p *authp) cmdIsAllowed(c app.CmdDetails, permLevel string) bool {
	permLevels, ok := p.perms[c.String()]
	if !ok {
		log.Errorf("Permission level has not been set for %v", c.String())
		return false
	}
	_, ok = permLevels[permLevel]
	return ok
}
