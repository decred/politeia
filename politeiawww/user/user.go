// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package user

import (
	"database/sql"

	"github.com/google/uuid"
)

type User struct {
	ID      uuid.UUID             // Unique ID
	Plugins map[string]PluginData // [pluginID]PluginData
}

type PluginData struct {
	ClearText []byte
	Encrypted []byte
}

type DB interface {
	Insert(u User) error
	Get(userID string) (*User, error)
	TxUpdate(tx *sql.Tx, pluginID string, clearText, encrypted []byte) error
	TxGet(tx *sql.Tx, userID string) (*User, error)
}
