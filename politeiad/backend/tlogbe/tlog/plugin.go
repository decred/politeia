// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlog

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe/plugins"
	"github.com/decred/politeia/politeiad/backend/tlogbe/plugins/comments"
	"github.com/decred/politeia/politeiad/backend/tlogbe/plugins/dcrdata"
	"github.com/decred/politeia/politeiad/backend/tlogbe/plugins/pi"
	cmplugin "github.com/decred/politeia/politeiad/plugins/comments"
	ddplugin "github.com/decred/politeia/politeiad/plugins/dcrdata"
	piplugin "github.com/decred/politeia/politeiad/plugins/pi"
)

const (
	// pluginDataDirname is the plugin data directory name. It is
	// located in the tlog instance data directory and is provided to
	// the plugins for storing plugin data.
	pluginDataDirname = "plugins"
)

// plugin represents a tlog plugin.
type plugin struct {
	id       string
	settings []backend.PluginSetting
	client   plugins.Client
}

func (t *Tlog) plugin(pluginID string) (plugin, bool) {
	t.Lock()
	defer t.Unlock()

	plugin, ok := t.plugins[pluginID]
	return plugin, ok
}

func (t *Tlog) pluginIDs() []string {
	t.Lock()
	defer t.Unlock()

	ids := make([]string, 0, len(t.plugins))
	for k := range t.plugins {
		ids = append(ids, k)
	}

	return ids
}

func (t *Tlog) PluginRegister(b backend.Backend, p backend.Plugin) error {
	log.Tracef("%v PluginRegister: %v", t.id, p.ID)

	var (
		client plugins.Client
		err    error

		dataDir = filepath.Join(t.dataDir, pluginDataDirname)
	)
	switch p.ID {
	case cmplugin.ID:
		client, err = comments.New(t, p.Settings, p.Identity, dataDir)
		if err != nil {
			return err
		}
	case ddplugin.ID:
		client, err = dcrdata.New(p.Settings, t.activeNetParams)
		if err != nil {
			return err
		}
	case piplugin.ID:
		client, err = pi.New(b, t, p.Settings, dataDir, t.activeNetParams)
		if err != nil {
			return err
		}
		/*
			case ticketvote.ID:
				client, err = newTicketVotePlugin(t, newBackendClient(t),
					p.Settings, p.Identity, t.activeNetParams)
				if err != nil {
					return err
				}
		*/
	default:
		return backend.ErrPluginInvalid
	}

	t.Lock()
	defer t.Unlock()

	t.plugins[p.ID] = plugin{
		id:       p.ID,
		settings: p.Settings,
		client:   client,
	}

	return nil
}

func (t *Tlog) PluginSetup(pluginID string) error {
	log.Tracef("%v PluginSetup: %v", t.id, pluginID)

	p, ok := t.plugin(pluginID)
	if !ok {
		return backend.ErrPluginInvalid
	}

	return p.client.Setup()
}

func (t *Tlog) PluginHookPre(h plugins.HookT, payload string) error {
	log.Tracef("%v PluginHookPre: %v %v", t.id, h, payload)

	// Pass hook event and payload to each plugin
	for _, v := range t.pluginIDs() {
		p, _ := t.plugin(v)
		err := p.client.Hook(h, payload)
		if err != nil {
			var e backend.PluginUserError
			if errors.As(err, &e) {
				return err
			}
			return fmt.Errorf("hook %v: %v", v, err)
		}
	}

	return nil
}

func (t *Tlog) PluginHookPost(h plugins.HookT, payload string) {
	log.Tracef("%v PluginHookPost: %v %v", t.id, h, payload)

	// Pass hook event and payload to each plugin
	for _, v := range t.pluginIDs() {
		p, ok := t.plugin(v)
		if !ok {
			log.Errorf("%v PluginHookPost: plugin not found %v", t.id, v)
			continue
		}
		err := p.client.Hook(h, payload)
		if err != nil {
			// This is the post plugin hook so the data has already been
			// saved to tlog. We do not have the ability to unwind. Log
			// the error and continue.
			log.Criticalf("%v PluginHookPost %v %v: %v: %v",
				t.id, v, h, err, payload)
			continue
		}
	}
}

func (t *Tlog) PluginCmd(treeID int64, token []byte, pluginID, cmd, payload string) (string, error) {
	log.Tracef("%v PluginCmd: %v %x %v %v", t.id, treeID, token, pluginID, cmd)

	// Get plugin
	p, ok := t.plugin(pluginID)
	if !ok {
		return "", backend.ErrPluginInvalid
	}

	// Execute plugin command
	return p.client.Cmd(treeID, token, cmd, payload)
}

func (t *Tlog) Plugins() []backend.Plugin {
	log.Tracef("%v Plugins", t.id)

	t.Lock()
	defer t.Unlock()

	plugins := make([]backend.Plugin, 0, len(t.plugins))
	for _, v := range t.plugins {
		plugins = append(plugins, backend.Plugin{
			ID:       v.id,
			Settings: v.settings,
		})
	}

	return plugins
}
