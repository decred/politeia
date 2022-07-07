// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

// App provides an API for accessing the plugin configuration of a politeia
// app. An app is essentially just a unique configuration of plugins and
// plugin settings.
type App interface {
	// Plugins returns all of the plugins that are part of the app.
	//
	// The provided plugin settings are the settings that were parsed from the
	// config file at runtime. These runtime settings should override any
	// existing plugin settings.
	Plugins(map[string][]Setting) ([]Plugin, error)

	// UserManager returns the app's UserManager.
	UserManager() (UserManager, error)

	// AuthManager returns the app's AuthManager.
	AuthManager() (AuthManager, error)
}

// Setting represents a configurable plugin setting.
//
// The value can either contain a single value or multiple values. Multiple
// values will be formatted as a JSON encoded []string.
type Setting struct {
	Key   string // Name of setting
	Value string // Value of setting
}
