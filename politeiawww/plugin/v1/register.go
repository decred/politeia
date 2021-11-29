// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

import "errors"

var (
	// ErrPluginNotFound is returned when a plugin that has not been registered
	// is attempted to be initialized.
	ErrPluginNotFound = errors.New("plugin not found")

	// Registered plugins
	plugins      = make(map[string]newPlugin)
	userManagers = make(map[string]newUserManager)
	authorizers  = make(map[string]newAuthorizer)
)

// PluginArgs contains the arguments used to initialize a plugin.
type PluginArgs struct {
	Settings []PluginSetting
}

// PluginSetting represents a configurable plugin setting.
//
// The value can either contain a single value or multiple values. Multiple
// values will be formatted as a JSON encoded []string.
type PluginSetting struct {
	Key   string // Name of setting
	Value string // Value of setting
}

type newPlugin func(PluginArgs) (Plugin, error)

type newUserManager func(PluginArgs) (UserManager, error)

type newAuthorizer func(PluginArgs) (Authorizer, error)

func RegisterPlugin(pluginID string, fn newPlugin) {
	plugins[pluginID] = fn
}

func RegisterUserManager(pluginID string, fn newUserManager) {
	userManagers[pluginID] = fn
}

func RegisterAuthorizer(pluginID string, fn newAuthorizer) {
	authorizers[pluginID] = fn
}

func NewPlugin(pluginID string) (Plugin, error) {
	return nil, nil
}

func NewUserManager(pluginID string) (UserManager, error) {
	return nil, nil
}

func NewAuthorizer(pluginID string) (Authorizer, error) {
	return nil, nil
}
