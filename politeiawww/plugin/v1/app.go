// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

// App provides an API for accessing the plugin configuration of a politeia
// app. An app is essentially just a unique configuration of plugins.
type App interface {
	// Plugins returns all of the plugins that are part of the app.
	//
	// The plugin settings that were parsed from the politeia config file at
	// runtime are provided. These settings should override the existing plugin
	// settings.
	Plugins(map[string][]Setting) ([]Plugin, error)

	// AuthManager returns the app's AuthManager.
	AuthManager() (AuthManager, error)

	// DisallowBatchedReads returns the list of plugin commands that are not
	// allowed to be included in a read batch.
	//
	// Prior to executing a read batch, the backend will verify that the read
	// commands are allowed to be executed as part of a read batch.  This lets
	// the app prevent expensive reads from being batched. By default, all read
	// commands are allowed to be batch.
	DisallowBatchedReads() []Cmd
}

// Setting represents a configurable plugin setting.
//
// The value can either contain a single value or multiple values. Multiple
// values will be formatted as a JSON encoded []string.
type Setting struct {
	Name  string
	Value string
}
