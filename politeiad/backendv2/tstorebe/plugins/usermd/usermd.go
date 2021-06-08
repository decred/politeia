// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package usermd

import (
	"os"
	"path/filepath"
	"sync"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/plugins/usermd"
)

var (
	_ plugins.PluginClient = (*usermdPlugin)(nil)
)

// usermdPlugin is the tstore backend implementation of the usermd plugin. The
// usermd plugin extends a record with user metadata.
//
// usermdPlugin satisfies the plugins PluginClient interface.
type usermdPlugin struct {
	sync.Mutex
	tstore plugins.TstoreClient

	// dataDir is the pi plugin data directory. The only data that is
	// stored here is cached data that can be re-created at any time
	// by walking the trillian trees.
	dataDir string
}

// Setup performs any plugin setup that is required.
//
// This function satisfies the plugins PluginClient interface.
func (p *usermdPlugin) Setup() error {
	log.Tracef("usermd Setup")

	return nil
}

// Write executes a read/write plugin command. All operations are executed
// atomically by tstore when using this method. The plugin does not need to
// worry about concurrency issues.
//
// This function satisfies the plugins PluginClient interface.
func (p *usermdPlugin) Write(token []byte, cmd, payload string) (string, error) {
	log.Tracef("usermd Write: %x %v %v", token, cmd, payload)

	return "", backend.ErrPluginCmdInvalid
}

// Read executes a read-only plugin command.
//
// This function satisfies the plugins PluginClient interface.
func (p *usermdPlugin) Read(token []byte, cmd, payload string) (string, error) {
	log.Tracef("usermd Read: %x %v %v", token, cmd, payload)

	switch cmd {
	case usermd.CmdAuthor:
		return p.cmdAuthor(token)
	case usermd.CmdUserRecords:
		return p.cmdUserRecords(payload)
	}

	return "", backend.ErrPluginCmdInvalid
}

// Hook executes a plugin hook.
//
// This function satisfies the plugins PluginClient interface.
func (p *usermdPlugin) Hook(h plugins.HookT, payload string) error {
	log.Tracef("usermd Hook: %v", plugins.Hooks[h])

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
		return p.hookSetRecordStatusPost(payload)
	}

	return nil
}

// Fsck performs a plugin filesystem check.
//
// This function satisfies the plugins PluginClient interface.
func (p *usermdPlugin) Fsck() error {
	log.Tracef("usermd Fsck")

	return nil
}

// Settings returns the plugin's settings.
//
// This function satisfies the plugins PluginClient interface.
func (p *usermdPlugin) Settings() []backend.PluginSetting {
	log.Tracef("usermd Settings")

	return nil
}

// New returns a new usermdPlugin.
func New(tstore plugins.TstoreClient, settings []backend.PluginSetting, dataDir string) (*usermdPlugin, error) {
	// Create plugin data directory
	dataDir = filepath.Join(dataDir, usermd.PluginID)
	err := os.MkdirAll(dataDir, 0700)
	if err != nil {
		return nil, err
	}

	return &usermdPlugin{
		tstore:  tstore,
		dataDir: dataDir,
	}, nil
}
