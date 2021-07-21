// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package user

import "github.com/google/uuid"

// MailerDB describes the interface used to interact with the email histories
// table from the user database, used by the mail client.
type MailerDB interface {
	// EmailHistoriesSave saves the provided email histories to the
	// database. The histories map contains map[userid]EmailHistory.
	EmailHistoriesSave(histories map[uuid.UUID]EmailHistory) error

	// EmailHistoriesGet retrieves the email histories for the provided
	// user IDs. The returned map[userid]EmailHistory will contain an
	// entry for each of the provided user ID. If a provided user ID
	// does not correspond to a user in the database then the entry will
	// be skipped in the returned map. An error is not returned.
	EmailHistoriesGet(users []uuid.UUID) (map[uuid.UUID]EmailHistory, error)
}

// EmailHistory keeps track of the received emails by each user. This is
// used to rate limit the amount of emails an user can receive in a 24h
// time window. This was not stored in the user object in order to avoid
// race conditions on db calls, since our user db currently does not support
// transactions, and email notifications run in a separate goroutine. This
// workaround won't be necessary once the user layer gets rewritten.
type EmailHistory struct {
	Timestamps []int64 `json:"timestamps"` // Received email UNIX ts

	// LimitWarningSent is used to track users that have hit the rate
	// limit and have already been sent a notification email letting
	// them know that they hit the rate limit.
	LimitWarningSent bool `json:"limitwarningsent"`
}

// VersionEmailHistory is the version of the EmailHistory struct.
const VersionEmailHistory uint32 = 1
