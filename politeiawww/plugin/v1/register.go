// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

import "github.com/pkg/errors"

var (
	// The following maps store the various initialization functions that have
	// been registered with this package.
	pluginInitFns      = make(map[string]func(InitArgs) (Plugin, error))
	userManagerInitFns = make(map[string]func(InitArgs) (UserManager, error))
	authManagerInitFns = make(map[string]func(InitArgs) (AuthManager, error))
)

// InitArgs contains the arguments used to initialize the plugin interface
// types.
type InitArgs struct {
	Settings []Setting
}

// Setting represents a configurable plugin setting.
//
// The value can either contain a single value or multiple values. Multiple
// values will be formatted as a JSON encoded []string.
type Setting struct {
	Key   string // Name of setting
	Value string // Value of setting
}

// RegisterPluginInitFn registers a Plugin initialization function with this
// package. This should be done by the plugin implementation as part of its
// package level init() function. The registered function is called at runtime
// to initialize the Plugin.
func RegisterPluginInitFn(pluginID string, fn func(InitArgs) (Plugin, error)) {
	pluginInitFns[pluginID] = fn
}

// RegisterUserManagerInitFn registers a UserManager initialization function
// with this package. This should be done by the plugin implementation as part
// of its package level init() function. The registered function is called at
// runtime to initialize the UserManager .
func RegisterUserManagerInitFn(pluginID string, fn func(InitArgs) (UserManager, error)) {
	userManagerInitFns[pluginID] = fn
}

// RegisterAuthManagerInitFn registers an AuthManager initialization function
// with this package. This should be done by the plugin implementation as part
// of its package level init() function. The registered function is called at
// runtime to initialize the AuthManager.
func RegisterAuthManagerInitFn(pluginID string, fn func(InitArgs) (AuthManager, error)) {
	authManagerInitFns[pluginID] = fn
}

// NewPlugin uses the registered plugin initialization function to initialize
// and return a Plugin.
func NewPlugin(pluginID string, args InitArgs) (Plugin, error) {
	fn, ok := pluginInitFns[pluginID]
	if !ok {
		return nil, errors.Errorf("plugin '%v' did not register "+
			"a plugin initialization function", pluginID)
	}
	return fn(args)
}

// NewUserManager uses the registered user manager initialization function to
// initialize and return a UserManager.
func NewUserManager(pluginID string, args InitArgs) (UserManager, error) {
	fn, ok := userManagerInitFns[pluginID]
	if !ok {
		return nil, errors.Errorf("plugin '%v' did not register "+
			"a user manager initialization function", pluginID)
	}
	return fn(args)
}

// NewAuthManager uses the registered authManager initialization function to
// initialize and return an AuthManager.
func NewAuthManager(pluginID string, args InitArgs) (AuthManager, error) {
	fn, ok := authManagerInitFns[pluginID]
	if !ok {
		return nil, errors.Errorf("plugin '%v' did not register "+
			"an auth manager initialization function", pluginID)
	}
	return fn(args)
}
