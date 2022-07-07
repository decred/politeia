// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"

	"github.com/decred/politeia/politeiawww/apps/proposals"
	plugin "github.com/decred/politeia/politeiawww/plugin/v1"
	"github.com/pkg/errors"
)

// setupApp sets up politeia to run the app that was specified in politeia
// configuration.
//
// An app is essentially just a unique configuation of plugins. politeia
// accesses the plugin configuration using the API provided by the plugin.App
// interface.
//
// Plugin settings that were specified in the config file are parsed and
// provided to the app. These runtime settings will override any existing app
// settings.
func (p *politeiawww) setupApp() error {
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

	// Initialize the app
	var (
		app plugin.App
		err error
	)
	switch p.cfg.App {
	case proposals.AppID:
		app, err = proposals.NewApp(settings)
		if err != nil {
			return err
		}

	default:
		return errors.Errorf("%v is not a valid app", p.cfg.App)
	}

	// Setup the app plugins
	plugins, err := app.Plugins(settings)
	if err != nil {
		return err
	}
	var (
		pluginsM  = make(map[string]plugin.Plugin, len(plugins))
		pluginIDs = make([]string, 0, len(plugins))
	)
	for _, v := range plugins {
		pluginsM[v.ID()] = v
		pluginIDs = append(pluginIDs, v.ID())
	}
	// Sort the plugin IDs alphabetically
	sort.SliceStable(pluginIDs, func(i, j int) bool {
		return pluginIDs[i] < pluginIDs[j]
	})
	userManager, err := app.UserManager()
	if err != nil {
		return err
	}
	authManager, err := app.AuthManager()
	if err != nil {
		return err
	}

	p.plugins = pluginsM
	p.pluginIDs = pluginIDs
	p.userManager = userManager
	p.authManager = authManager

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
		settingName  = parsed[1]
		settingValue = parsed[2]
	)

	// Clean the strings. The setting value is allowed to be case
	// sensitive.
	pluginID = strings.ToLower(strings.TrimSpace(pluginID))
	settingName = strings.ToLower(strings.TrimSpace(settingName))
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
		Name:  settingName,
		Value: settingValue,
	}, nil
}

var (
	// regexpPluginSettingMulti matches against the plugin setting value when it
	// contains multiple values.
	//
	// pluginID,key,["value1","value2"] matches ["value1","value2"]
	regexpPluginSettingMulti = regexp.MustCompile(`(\[.*\]$)`)
)
