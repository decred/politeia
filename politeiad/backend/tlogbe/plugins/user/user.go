// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package user

import (
	"os"
	"path/filepath"
	"sync"

	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe/plugins"
	"github.com/decred/politeia/politeiad/plugins/user"
)

var (
	_ plugins.PluginClient = (*userPlugin)(nil)
)

type userPlugin struct {
	sync.Mutex
	tlog plugins.TlogClient

	// dataDir is the pi plugin data directory. The only data that is
	// stored here is cached data that can be re-created at any time
	// by walking the trillian trees.
	dataDir string
}

// Setup performs any plugin setup that is required.
//
// This function satisfies the plugins.PluginClient interface.
func (p *userPlugin) Setup() error {
	log.Tracef("Setup")

	return nil
}

// Cmd executes a plugin command.
//
// This function satisfies the plugins.PluginClient interface.
func (p *userPlugin) Cmd(treeID int64, token []byte, cmd, payload string) (string, error) {
	log.Tracef("Cmd: %v %x %v %v", treeID, token, cmd, payload)

	switch cmd {
	case user.CmdAuthor:
		return p.cmdAuthor(treeID)
	case user.CmdUserRecords:
		return p.cmdUserRecords(payload)
	}

	return "", backend.ErrPluginCmdInvalid
}

// Hook executes a plugin hook.
//
// This function satisfies the plugins.PluginClient interface.
func (p *userPlugin) Hook(treeID int64, token []byte, h plugins.HookT, payload string) error {
	log.Tracef("Hook: %v %x %v", treeID, token, plugins.Hooks[h])

	switch h {
	case plugins.HookTypeNewRecordPre:
		return p.hookNewRecordPre(payload)
	case plugins.HookTypeNewRecordPost:
		return p.hookNewRecordPost(payload)
	case plugins.HookTypeEditRecordPre:
		return p.hookEditRecordPre(payload)
	case plugins.HookTypeEditMetadataPre:
		return p.hookEditMetadataPre(payload)
	case plugins.HookTypeSetRecordStatusPre:
		return p.hookSetRecordStatusPre(payload)
	}

	return nil
}

// Fsck performs a plugin filesystem check.
//
// This function satisfies the plugins.PluginClient interface.
func (p *userPlugin) Fsck(treeIDs []int64) error {
	log.Tracef("Fsck")

	return nil
}

// TODO Settings returns the plugin's settings.
//
// This function satisfies the plugins.PluginClient interface.
func (p *userPlugin) Settings() []backend.PluginSetting {
	log.Tracef("Settings")

	return nil
}

// New returns a new userPlugin.
func New(tlog plugins.TlogClient, settings []backend.PluginSetting, dataDir string) (*userPlugin, error) {
	// Create plugin data directory
	dataDir = filepath.Join(dataDir, user.PluginID)
	err := os.MkdirAll(dataDir, 0700)
	if err != nil {
		return nil, err
	}

	return &userPlugin{
		tlog:    tlog,
		dataDir: dataDir,
	}, nil
}
