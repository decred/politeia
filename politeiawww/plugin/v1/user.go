// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

import "github.com/google/uuid"

type User struct {
	ID         uuid.UUID // Unique ID
	PluginData *PluginData
}

// PluginData contains the user data that is owned by the plugin.
//
// These fields can be updated by the plugin during execution of a write
// command. The PluginData methods MUST be used if the plugin wants the changes
// persisted. Updates made using the PluginData methods will be persisted by
// the caller. Any updates made during the execution of a read-only command
// will be ignored.
//
// The encrypted data blob will be provided to the plugin as clear text, but
// will be saved to the database by the caller as encrypted. The plugin does
// not need to worry about encrypting/decrypting the data.
type PluginData struct {
	clearText []byte
	encrypted []byte
	updated   bool
}

func NewPluginData(clearText, encrypted []byte) *PluginData {
	return &PluginData{
		clearText: clearText,
		encrypted: encrypted,
	}
}

func (d *PluginData) ClearText() []byte {
	return d.clearText
}

func (d *PluginData) SetClearText(b []byte) {
	d.clearText = b
	d.updated = true
}

func (d *PluginData) Encrypted() []byte {
	return d.encrypted
}

func (d *PluginData) SetEncrypted(b []byte) {
	d.encrypted = b
	d.updated = true
}

func (d *PluginData) Updated() bool {
	return d.updated
}
