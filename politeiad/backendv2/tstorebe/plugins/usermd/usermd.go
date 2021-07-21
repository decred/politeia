// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package usermd

import (
	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/plugins/usermd"
)

var (
	_ plugins.PluginClient = (*usermdPlugin)(nil)
)

// usermdPlugin is the tstore backend implementation of the usermd plugin API.
// The usermd plugin extends a record with user metadata.
//
// usermdPlugin satisfies the plugins PluginClient interface.
type usermdPlugin struct{}

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
func (p *usermdPlugin) Write(tstore plugins.TstoreClient, token []byte, cmd, payload string) (string, error) {
	log.Tracef("usermd Write: %x %v %v", token, cmd, payload)

	return "", backend.ErrPluginCmdInvalid
}

// Read executes a read-only plugin command.
//
// This function satisfies the plugins PluginClient interface.
func (p *usermdPlugin) Read(tstore plugins.TstoreClient, token []byte, cmd, payload string) (string, error) {
	log.Tracef("usermd Read: %x %v %v", token, cmd, payload)

	switch cmd {
	case usermd.CmdAuthor:
		return p.cmdAuthor(tstore, token)
	case usermd.CmdUserRecords:
		return p.cmdUserRecords(tstore, payload)
	}

	return "", backend.ErrPluginCmdInvalid
}

// Hook executes a plugin hook.
//
// This function satisfies the plugins PluginClient interface.
func (p *usermdPlugin) Hook(tstore plugins.TstoreClient, h plugins.HookT, payload string) error {
	log.Tracef("usermd Hook: %v", plugins.Hooks[h])

	switch h {
	case plugins.HookRecordNewPre:
		return p.hookRecordNewPre(payload)
	case plugins.HookRecordNewPost:
		return p.hookRecordNewPost(tstore, payload)
	case plugins.HookRecordEditPre:
		return p.hookRecordEditPre(payload)
	case plugins.HookRecordEditMetadataPre:
		return p.hookRecordEditMetadataPre(payload)
	case plugins.HookRecordSetStatusPre:
		return p.hookRecordSetStatusPre(payload)
	case plugins.HookRecordSetStatusPost:
		return p.hookRecordSetStatusPost(tstore, payload)
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
func New() *usermdPlugin {
	return &usermdPlugin{}
}
