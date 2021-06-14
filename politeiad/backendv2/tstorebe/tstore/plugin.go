// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tstore

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins/comments"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins/dcrdata"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins/pi"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	cmplugin "github.com/decred/politeia/politeiad/plugins/comments"
	ddplugin "github.com/decred/politeia/politeiad/plugins/dcrdata"
	piplugin "github.com/decred/politeia/politeiad/plugins/pi"
	tkplugin "github.com/decred/politeia/politeiad/plugins/ticketvote"
	umplugin "github.com/decred/politeia/politeiad/plugins/usermd"
)

const (
	// pluginDataDirname is the plugin data directory name. It is
	// located in the tstore backend data directory and is provided
	// to the plugins for storing plugin data.
	pluginDataDirname = "plugins"
)

// plugin represents a tstore plugin.
type plugin struct {
	id     string
	client plugins.PluginClient
}

// plugin returns the specified plugin. Only plugins that have been registered
// will be returned.
func (t *Tstore) plugin(pluginID string) (plugin, bool) {
	t.Lock()
	defer t.Unlock()

	plugin, ok := t.plugins[pluginID]
	return plugin, ok
}

// pluginIDs returns the plugin ID of all registered plugins.
func (t *Tstore) pluginIDs() []string {
	t.Lock()
	defer t.Unlock()

	ids := make([]string, 0, len(t.plugins))
	for k := range t.plugins {
		ids = append(ids, k)
	}

	// Sort IDs so the returned order is deterministic
	sort.SliceStable(ids, func(i, j int) bool {
		return ids[i] < ids[j]
	})

	return ids
}

// PluginRegister registers a plugin. Plugin commands and hooks can be executed
// on the plugin once registered.
func (t *Tstore) PluginRegister(b backend.Backend, p backend.Plugin) error {
	log.Tracef("PluginRegister: %v", p.ID)

	var (
		client plugins.PluginClient
		err    error

		dataDir = filepath.Join(t.dataDir, pluginDataDirname)
	)
	switch p.ID {
	case cmplugin.PluginID:
		client, err = comments.New(p.Settings, p.Identity)
		if err != nil {
			return err
		}
	case ddplugin.PluginID:
		client, err = dcrdata.New(p.Settings, t.activeNetParams)
		if err != nil {
			return err
		}
	case piplugin.PluginID:
		client, err = pi.New(b, p.Settings, dataDir)
		if err != nil {
			return err
		}
	case tkplugin.PluginID:
		/* TODO
		client, err = ticketvote.New(b, t, p.Settings, dataDir,
			p.Identity, t.activeNetParams)
		if err != nil {
			return err
		}
		*/
	case umplugin.PluginID:
		/* TODO
		client, err = usermd.New(t, p.Settings, dataDir)
		if err != nil {
			return err
		}
		*/
	default:
		return backend.ErrPluginIDInvalid
	}

	t.Lock()
	defer t.Unlock()

	t.plugins[p.ID] = plugin{
		id:     p.ID,
		client: client,
	}

	return nil
}

// PluginSetup performs any required setup for the specified plugin.
func (t *Tstore) PluginSetup(pluginID string) error {
	log.Tracef("PluginSetup: %v", pluginID)

	p, ok := t.plugin(pluginID)
	if !ok {
		return backend.ErrPluginIDInvalid
	}

	return p.client.Setup()
}

// PluginHookPre executes a tstore backend pre hook. Pre hooks are hooks that
// are executed prior to the tstore backend writing data to disk. These hooks
// give plugins the opportunity to add plugin specific validation to record
// methods or plugin commands that write data.
func (t *Tstore) PluginHookPre(tx store.Tx, h plugins.HookT, payload string) error {
	log.Tracef("PluginHookPre: %v", plugins.Hooks[h])

	// Pass hook event and payload to each plugin
	for _, pid := range t.pluginIDs() {
		// Setup the tstore client
		clientID := fmt.Sprintf("%v hook: %v:", pid, plugins.Hooks[h])
		c := newClient(clientID, t, tx, nil)

		// Setup the plugin
		p, _ := t.plugin(pid)

		// Execute the hook
		err := p.client.Hook(c, h, payload)
		if err != nil {
			var e backend.PluginError
			if errors.As(err, &e) {
				return err
			}
			return fmt.Errorf("hook %v: %v", pid, err)
		}
	}

	return nil
}

// PluginHookPre executes a tstore backend post hook. Post hooks are hooks that
// are executed after the tstore backend successfully writes data to disk.
// These hooks give plugins the opportunity to cache data from the write.
func (t *Tstore) PluginHookPost(tx store.Tx, h plugins.HookT, payload string) {
	log.Tracef("PluginHookPost: %v", plugins.Hooks[h])

	// Pass hook event and payload to each plugin
	for _, pid := range t.pluginIDs() {
		// Setup the tstore client
		clientID := fmt.Sprintf("%v hook: %v:", pid, plugins.Hooks[h])
		c := newClient(clientID, t, tx, nil)

		// Setup the plugin
		p, ok := t.plugin(pid)
		if !ok {
			log.Errorf("%v PluginHookPost: plugin not found %v", pid)
			continue
		}

		// Execute the hook
		err := p.client.Hook(c, h, payload)
		if err != nil {
			// This is the post plugin hook so the data has already been
			// saved to tstore. We do not have the ability to unwind. Log
			// the error and continue.
			log.Criticalf("%v PluginHookPost %v %v: %v: %v",
				pid, h, err, payload)
			continue
		}
	}
}

// PluginWrite executes a read/write plugin command.
func (t *Tstore) PluginWrite(tx store.Tx, token []byte, pluginID, cmd, payload string) (string, error) {
	log.Tracef("PluginWrite: %x %v %v", token, pluginID, cmd)

	// Get plugin
	p, ok := t.plugin(pluginID)
	if !ok {
		return "", backend.ErrPluginIDInvalid
	}

	// Setup tstore client
	clientID := fmt.Sprintf("%v read: %v:", pluginID, cmd)
	c := newClient(clientID, t, tx, nil)

	// Execute plugin command
	return p.client.Write(c, token, cmd, payload)
}

// PluginRead executes a read-only plugin command.
func (t *Tstore) PluginRead(token []byte, pluginID, cmd, payload string) (string, error) {
	log.Tracef("PluginRead: %x %v %v", token, pluginID, cmd)

	// The token is optional
	if len(token) > 0 {
		// Read methods are allowed to use short tokens. Lookup the full
		// length token.
		var err error
		token, err = t.fullLengthToken(token)
		if err != nil {
			return "", err
		}
	}

	// Get plugin
	p, ok := t.plugin(pluginID)
	if !ok {
		return "", backend.ErrPluginIDInvalid
	}

	// Setup tstore client
	clientID := fmt.Sprintf("%v read: %v:", pluginID, cmd)
	c := newClient(clientID, t, nil, t.store)

	// Execute plugin command
	return p.client.Read(c, token, cmd, payload)
}

// Plugins returns all registered plugins for the tstore instance.
func (t *Tstore) Plugins() []backend.Plugin {
	log.Tracef("Plugins")

	t.Lock()
	defer t.Unlock()

	plugins := make([]backend.Plugin, 0, len(t.plugins))
	for _, v := range t.plugins {
		plugins = append(plugins, backend.Plugin{
			ID:       v.id,
			Settings: v.client.Settings(),
		})
	}

	return plugins
}
