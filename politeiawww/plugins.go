// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"strings"

	plugin "github.com/decred/politeia/politeiawww/plugin/v1"
	"github.com/pkg/errors"
)

// setupPlugins initializes the plugins that have been specified in the
// politeiawww config. The config plugin settings are parsed during this
// process and passed to the appropriate plugin on initialization.
func (p *politeiawww) setupPlugins() error {
	// Parse the plugin settings
	settings := make(map[string][]plugin.Setting)
	for _, rawSetting := range p.cfg.PluginSettings {
		pluginID, s, err := parsePluginSetting(rawSetting)
		if err != nil {
			return errors.Errorf("failed to parse %v", rawSetting)
		}
		ss, ok := settings[pluginID]
		if !ok {
			ss = make([]plugin.Setting, 0, 16)
		}
		ss = append(ss, *s)
		settings[pluginID] = ss
	}

	// Initialize the plugins
	plugins := make(map[string]plugin.Plugin, len(p.cfg.Plugins))
	for _, pluginID := range p.cfg.Plugins {
		s, ok := settings[pluginID]
		if !ok {
			s = []plugin.Setting{}
		}
		args := plugin.InitArgs{
			Settings: s,
		}
		pp, err := plugin.NewPlugin(pluginID, args)
		if err != nil {
			return errors.Errorf("failed to initialize %v", pluginID)
		}
		plugins[pluginID] = pp
	}

	// Initialize the user plugin interfaces
	var (
		um  plugin.UserManager
		am  plugin.AuthManager
		err error
	)
	if !p.cfg.DisableUsers {
		if p.cfg.UserPlugin == "" {
			return errors.Errorf("user plugin not provided; a user " +
				"plugin must be provided when the user layer is enabled")
		}
		if p.cfg.AuthPlugin == "" {
			return errors.Errorf("auth plugin not provided; an auth " +
				"plugin must be provided when the user layer is enabled")
		}

		// Initialize the user manager
		s, ok := settings[p.cfg.UserPlugin]
		if !ok {
			s = []plugin.Setting{}
		}
		args := plugin.InitArgs{
			Settings: s,
		}
		um, err = plugin.NewUserManager(p.cfg.UserPlugin, args)
		if err != nil {
			return errors.Errorf("failed to initialize the user manager plugin %v",
				p.cfg.UserPlugin)
		}

		// Initialize the authorizer
		s, ok = settings[p.cfg.AuthPlugin]
		if !ok {
			s = []plugin.Setting{}
		}
		args = plugin.InitArgs{
			Settings: s,
		}
		am, err = plugin.NewAuthManager(p.cfg.AuthPlugin, args)
		if err != nil {
			return errors.Errorf("failed to initialize the auth manager plugin %v",
				p.cfg.AuthPlugin)
		}
	}

	// Set the user plugin fields
	p.pluginIDs = p.cfg.Plugins
	p.plugins = plugins
	p.userManager = um
	p.authManager = am

	return nil
}

// parsePluginSetting parses a plugin setting. Plugin settings will be in
// following format. The value may be a single value or an array of values.
//
// pluginID,key,value
// pluginID,key,["value1","value2","value3"...]
//
// When multiple values are provided, the values must be formatted as a JSON
// encoded []string. Both of the following JSON formats are acceptable.
//
// pluginID,key,["value1","value2","value3"]
// pluginsetting="pluginID,key,[\"value1\",\"value2\",\"value3\"]"
func parsePluginSetting(setting string) (string, *plugin.Setting, error) {
	formatMsg := `expected plugin setting format is ` +
		`pluginID,key,value OR pluginID,key,["value1","value2","value3"]`

	// Parse the plugin setting
	var (
		parsed = strings.Split(setting, ",")

		// isMulti indicates whether the plugin setting contains
		// multiple values. If the setting only contains a single
		// value then isMulti will be false.
		isMulti = regexpPluginSettingMulti.MatchString(setting)
	)
	switch {
	case len(parsed) < 3:
		return "", nil, errors.Errorf("missing csv entry '%v'; %v",
			setting, formatMsg)
	case len(parsed) == 3:
		// This is expected; continue
	case len(parsed) > 3 && isMulti:
		// This is expected; continue
	default:
		return "", nil, errors.Errorf("invalid format '%v'; %v",
			setting, formatMsg)
	}

	var (
		pluginID     = parsed[0]
		settingKey   = parsed[1]
		settingValue = parsed[2]
	)

	// Clean the strings. The setting value is allowed to be case
	// sensitive.
	pluginID = strings.ToLower(strings.TrimSpace(pluginID))
	settingKey = strings.ToLower(strings.TrimSpace(settingKey))
	settingValue = strings.TrimSpace(settingValue)

	// Handle multiple values
	if isMulti {
		// Parse values
		values := regexpPluginSettingMulti.FindString(setting)

		// Verify the values are formatted as valid JSON
		var s []string
		err := json.Unmarshal([]byte(values), &s)
		if err != nil {
			return "", nil, err
		}

		// Re-encode the JSON. This will remove any funny
		// formatting like whitespaces.
		b, err := json.Marshal(s)
		if err != nil {
			return "", nil, err
		}

		// Save the value
		settingValue = string(b)
	}

	return pluginID, &plugin.Setting{
		Key:   settingKey,
		Value: settingValue,
	}, nil
}
