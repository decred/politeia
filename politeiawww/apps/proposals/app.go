// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package proposals

import (
	plugin "github.com/decred/politeia/politeiawww/plugin/v1"
	"github.com/decred/politeia/politeiawww/plugins/auth"
)

const (
	// AppID is the app ID for the proposals app.
	AppID = "proposals"
)

var _ plugin.App = (*app)(nil)

// app satisfies the plugin/v1 App interface.
type app struct{}

// NewApp returns a new proposals app.
func NewApp(settings map[string][]plugin.Setting) (*app, error) {
	return &app{}, nil
}

func (a *app) Plugins(plugins map[string][]plugin.Setting) ([]plugin.Plugin, error) {
	return nil, nil
}

func (a *app) UserManager() (plugin.UserManager, error) {
	return nil, nil
}

func (a *app) AuthManager() (plugin.AuthManager, error) {
	authP := auth.NewPlugin()

	// Setup the user permissions for the plugin
	// cmds that are part of the proposals.
	err := authP.SetCmdPerms(perms())
	if err != nil {
		return nil, err
	}

	return authP, nil
}
