// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

import "github.com/google/uuid"

// User represents a politeia user. The user will contain the PluginData for
// the plugin that is executing the command or hook.
type User struct {
	ID         uuid.UUID // Unique ID
	PluginData *PluginData
}

// PluginData contains the user data that is owned by the plugin.
//
// These fields can be updated by the plugin during execution of write
// commands. Updates are persisted by the backend on successful completion of
// the plugin command execution. Any updates made during the execution of
// read-only commands are ignored.
//
// The encrypted data blob will be provided to the plugin as clear text, but
// will be saved to the database by the backend as encrypted. The plugin does
// not need to worry about encrypting/decrypting the data.
type PluginData struct {
	clearText []byte
	encrypted []byte
	updated   bool
}

// NewPluginData returns a new PluginData.
func NewPluginData(clearText, encrypted []byte) *PluginData {
	return &PluginData{
		clearText: clearText,
		encrypted: encrypted,
	}
}

// ClearText returns the clear text plugin data.
func (d *PluginData) ClearText() []byte {
	return d.clearText
}

// SetClearText updates the clear text plugin data.
func (d *PluginData) SetClearText(b []byte) {
	d.clearText = b
	d.updated = true
}

// Encrypted returns the encrypted plugin data. The data is returned as clear
// text to the plugin, but is saved to the database as encrypted. The plugin
// does not need to worry about encrypting/decrypting the data.
func (d *PluginData) Encrypted() []byte {
	return d.encrypted
}

// SetEncrypted updates the encrypted plugin data. The provided data should be
// clear text. It will be encrypted prior to being saved to the database. The
// plugin does not need to worry about encrypting/decrypting the data.
func (d *PluginData) SetEncrypted(b []byte) {
	d.encrypted = b
	d.updated = true
}

// Updated returns whether the plugin data has been updated.
func (d *PluginData) Updated() bool {
	return d.updated
}
