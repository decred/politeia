// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package user

import (
	"sync"

	"github.com/google/uuid"
)

// TestMailerDB implements the MailerDB interface that is used for testing
// purposes. It saves and retrieves data in memory to emulate the behaviour
// needed to test the mail package.
type TestMailerDB struct {
	sync.RWMutex

	Histories map[uuid.UUID]EmailHistory
}

// EmailHistoriesSave implements the save function using the in memory cache
// for testing purposes.
//
// This function satisfies the MailerDB interface.
func (m *TestMailerDB) EmailHistoriesSave(histories map[uuid.UUID]EmailHistory) error {
	m.Lock()
	defer m.Unlock()

	for email, history := range histories {
		m.Histories[email] = history
	}

	return nil
}

// EmailHistoriesGet implements the get function for the in memory cache used
// for testing purposes.
//
// This function satisfies the MailerDB interface.
func (m *TestMailerDB) EmailHistoriesGet(users []uuid.UUID) (map[uuid.UUID]EmailHistory, error) {
	m.RLock()
	defer m.RUnlock()

	histories := make(map[uuid.UUID]EmailHistory, len(users))
	for _, userID := range users {
		h, ok := m.Histories[userID]
		if !ok {
			// User email history does not exist, skip adding this
			// entry to the returned user email history map.
			continue
		}
		histories[userID] = h
	}
	return histories, nil
}

// NewTestMailerDB returns a new TestMailerDB instance.
func NewTestMailerDB() *TestMailerDB {
	return &TestMailerDB{
		Histories: make(map[uuid.UUID]EmailHistory, 5),
	}
}
