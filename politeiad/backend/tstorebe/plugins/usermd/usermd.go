// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package usermd

import (
	"os"
	"path/filepath"
	"sync"

	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/plugins/usermd"
)

var (
	_ plugins.PluginClient = (*userPlugin)(nil)
)

type userPlugin struct {
	sync.Mutex
	tstore plugins.TstoreClient

	// dataDir is the pi plugin data directory. The only data that is
	// stored here is cached data that can be re-created at any time
	// by walking the trillian trees.
	dataDir string
}

// Setup performs any plugin setup that is required.
//
// This function satisfies the plugins.PluginClient interface.
func (p *userPlugin) Setup() error {
	log.Tracef("usermd Setup")

	return nil
}

// Cmd executes a plugin command.
//
// This function satisfies the plugins.PluginClient interface.
func (p *userPlugin) Cmd(treeID int64, token []byte, cmd, payload string) (string, error) {
	log.Tracef("usermd Cmd: %v %x %v %v", treeID, token, cmd, payload)

	switch cmd {
	case usermd.CmdAuthor:
		return p.cmdAuthor(treeID)
	case usermd.CmdUserRecords:
		return p.cmdUserRecords(payload)
	}

	return "", backend.ErrPluginCmdInvalid
}

// Hook executes a plugin hook.
//
// This function satisfies the plugins.PluginClient interface.
func (p *userPlugin) Hook(treeID int64, token []byte, h plugins.HookT, payload string) error {
	log.Tracef("usermd Hook: %v %x %v", treeID, token, plugins.Hooks[h])

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
	case plugins.HookTypeSetRecordStatusPost:
		return p.hookSetRecordStatusPost(treeID, payload)
	}

	return nil
}

// Fsck performs a plugin filesystem check.
//
// This function satisfies the plugins.PluginClient interface.
func (p *userPlugin) Fsck(treeIDs []int64) error {
	log.Tracef("usermd Fsck")

	return nil
}

// Settings returns the plugin's settings.
//
// This function satisfies the plugins.PluginClient interface.
func (p *userPlugin) Settings() []backend.PluginSetting {
	log.Tracef("usermd Settings")

	return nil
}

// New returns a new userPlugin.
func New(tstore plugins.TstoreClient, settings []backend.PluginSetting, dataDir string) (*userPlugin, error) {
	// Create plugin data directory
	dataDir = filepath.Join(dataDir, usermd.PluginID)
	err := os.MkdirAll(dataDir, 0700)
	if err != nil {
		return nil, err
	}

	return &userPlugin{
		tstore:  tstore,
		dataDir: dataDir,
	}, nil
}
