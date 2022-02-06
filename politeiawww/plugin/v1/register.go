// Copyright (c) 2021-2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

import "github.com/pkg/errors"

var (
	// The following maps store the various initialization functions that have
	// been registered with this pacakge.
	pluginInitFns      = make(map[string]func(InitArgs) (Plugin, error))
	userManagerInitFns = make(map[string]func(InitArgs) (UserManager, error))
	authorizerInitFns  = make(map[string]func(InitArgs) (Authorizer, error))
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
// to intialize the Plugin.
func RegisterPluginInitFn(pluginID string, fn func(InitArgs) (Plugin, error)) {
	pluginInitFns[pluginID] = fn
}

// RegisterUserManagerInitFn registers a UserManager initialization function
// with this package. This should be done by the plugin implementation as part
// of its package level init() function. The registered function is called at
// runtime to intialize the UserManager .
func RegisterUserManagerInitFn(pluginID string, fn func(InitArgs) (UserManager, error)) {
	userManagerInitFns[pluginID] = fn
}

// RegisterAuthorizerInitFn registers an Authorizer initialization function
// with this package. This should be done by the plugin implementation as part
// of its package level init() function. The registered function is called at
// runtime to intialize the Authorizer.
func RegisterAuthorizerInitFn(pluginID string, fn func(InitArgs) (Authorizer, error)) {
	authorizerInitFns[pluginID] = fn
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

// NewAuthorizer uses the registered authorizer initialization function to
// initialize and return an Authorizer.
func NewAuthorizer(pluginID string, args InitArgs) (Authorizer, error) {
	fn, ok := authorizerInitFns[pluginID]
	if !ok {
		return nil, errors.Errorf("plugin '%v' did not register "+
			"an authorizer initialization function", pluginID)
	}
	return fn(args)
}
