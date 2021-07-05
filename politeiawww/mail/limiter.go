// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mail

import (
	"fmt"
	"time"

	"github.com/decred/politeia/politeiawww/user"
	"github.com/google/uuid"
)

// Limiter wraps around Client from the mail package and adds a
// email rate limit functionality for users.
type limiter struct {
	client client
	userDB user.Database
	limit  int

	userEmails map[string]uuid.UUID
}

var (
	_ Mailer = (*limiter)(nil)
)

// IsEnabled returns whether the mail server is enabled.
//
// This function satisfies the Mailer interface.
func (l *limiter) IsEnabled() bool {
	return l.client.disabled
}

// SendTo sends an email with the given subject and body to the provided list
// of email addresses. This also adds an email rate limit functionality ...
//
// This function satisfies the Mailer interface.
func (l *limiter) SendTo(subjects, body string, recipients []string) error {
	fmt.Println("sending mails via limiter")

	// Compile user IDs from recipients and get their email histories
	userIDs := make([]uuid.UUID, 0, len(recipients))
	for _, email := range recipients {
		userIDs = append(userIDs, l.userEmails[email])
	}
	histories, err := l.userDB.EmailHistoriesGet(userIDs)
	if err != nil {
		return fmt.Errorf("fetch histories from DB: %w", err)
	}

	// Divide recipients into valid and invalid recipients. This handles
	// sending email to users who have not hit the rate limit, and warning
	// users that their rate limit has been hit. Also, updates their email
	// histories on the db.
	var (
		valid   []string // Valid recipients (rate limit not hit)
		invalid []string // Invalid recipients (rate limit hit)

		newHistories = make(map[uuid.UUID]user.EmailHistory, len(recipients))
	)
	for _, email := range recipients {
		id := l.userEmails[email]
		history, ok := histories[id]
		if !ok {
			// User does not have a mail history yet, add user to valid
			// recipients and create his email history.
			newHistories[id] = user.EmailHistory{
				Timestamps:       []int64{time.Now().Unix()},
				LimitWarningSent: false,
			}
			valid = append(valid, email)
			continue
		}

		// Filter timestamps for the past 24h.
		history.Timestamps = l.filterTimestamps(history.Timestamps,
			24*time.Hour)

		if len(history.Timestamps) > l.limit {
			// Rate limit has been hit. If limit warning email has not yet
			// been sent, add user to invalid recipients and update email
			// history.
			if !history.LimitWarningSent {
				invalid = append(invalid, email)
				history.LimitWarningSent = true
				newHistories[id] = history
			}
			continue
		}

		// Rate limit has not been hit, add user to valid recipients and
		// update email history.
		valid = append(valid, email)
		history.Timestamps = append(history.Timestamps, time.Now().Unix())
		newHistories[id] = history
	}

	// Handle valid recipients.
	if len(valid) > 0 {
		err := l.client.SendTo(subjects, body, valid)
		if err != nil {
			return err
		}
	}

	// Handle invalid recipients.
	if len(invalid) > 0 {
		err := l.client.SendTo("rate limit hit", "rate limit hit", invalid)
		if err != nil {
			return err
		}
	}

	// Update email histories on db.
	l.userDB.EmailHistoriesSave(newHistories)

	return nil
}

func (l *limiter) filterTimestamps(in []int64, delta time.Duration) []int64 {
	staleBefore := time.Now().Add(-delta)
	out := make([]int64, 0, len(in))

	for _, ts := range in {
		timestamp := time.Unix(ts, 0)
		if timestamp.Before(staleBefore) {
			continue
		}
		out = append(out, ts)
	}

	return out
}

func newLimiter(c client, db user.Database, l int, ue map[string]uuid.UUID) *limiter {
	return &limiter{
		client:     c,
		userDB:     db,
		limit:      l,
		userEmails: ue,
	}
}
