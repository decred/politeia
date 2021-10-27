// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package user

import "github.com/google/uuid"

type User struct {
	ID          uuid.UUID // Unique ID
	Deactivated bool
	PluginData  PluginData
}

type PluginData struct {
	ClearText map[string][]byte // [pluginID]data
	Encrypted map[string][]byte // [pluginID]data
}

type DB interface {
	Insert(u User) error
	Update(u User) error
	Get(uuid string) (*User, error)
}
