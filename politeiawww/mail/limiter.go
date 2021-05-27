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

// Limiter is a wrapper around Mailer for implementing rate limiting functionality.
type Limiter struct {
	mailer Mailer
	userDB user.Database
	// limit defines max amount of emails a recipient can receive within last 24h.
	limit int
}

func NewLimiter(mailer Mailer, userDB user.Database, limit int) *Limiter {
	return &Limiter{
		mailer: mailer,
		userDB: userDB,
		limit:  limit,
	}
}

// IsEnabled returns whether the mail server is enabled.
func (l *Limiter) IsEnabled() bool {
	return l.mailer.IsEnabled()
}

func (l *Limiter) SendTo(subject, body string, recipients []string) error {
	return l.mailer.SendTo(subject, body, recipients)
}

func (l *Limiter) SendToUsers(subject, body string, recipients map[uuid.UUID]string) error {
	userIDs := make([]uuid.UUID, 0, len(recipients))
	for userID := range recipients {
		userIDs = append(userIDs, userID)
	}
	histories, err := l.userDB.EmailHistoriesGet(userIDs)
	if err != nil {
		return fmt.Errorf("fetch histories from DB: %w", err)
	}

	var (
		// Optimize for good recipients (those who won't hit rate limit).
		good          = make([]string, 0, len(recipients))
		goodHistories = make(map[uuid.UUID]user.EmailHistory, len(recipients))
		bad           []string
		badHistories  = make(map[uuid.UUID]user.EmailHistory)
	)

	for userID, email := range recipients {
		history := histories[userID]
		history.SentTimestamps = l.filterOutStaleTimestamps(history.SentTimestamps, 24*time.Hour)

		if len(history.SentTimestamps) < l.limit {
			// Previous history is fine, no rate limiting is necessary.
			good = append(good, email)
			goodHistories[userID] = history
			continue
		}
		if history.LimitWarningSent {
			// Rate limit is hit, but warning message has already been sent.
			continue
		}
		// Rate limit is hit.
		bad = append(bad, email)
		badHistories[userID] = history
	}

	if len(good) > 0 {
		err = l.mailer.SendTo(subject, body, good)
		if err != nil {
			return fmt.Errorf("send mail: %w", err)
		}

		err = l.refreshHistories(goodHistories, false)
		if err != nil {
			return fmt.Errorf("refresh histories: %w", err)
		}
	}

	if len(bad) > 0 {
		err = l.mailer.SendTo(subject, body, bad)
		if err != nil {
			return fmt.Errorf("send mail: %w", err)
		}
		err = l.refreshHistories(badHistories, true)
		if err != nil {
			return fmt.Errorf("refresh histories: %w", err)
		}
	}

	return nil
}

func (l *Limiter) refreshHistories(histories map[uuid.UUID]user.EmailHistory, limitWarningSent bool) error {
	for userID, history := range histories {
		history.SentTimestamps = append(history.SentTimestamps, time.Now())
		history.SentTimestamps = l.filterOutStaleTimestamps(history.SentTimestamps, 24*time.Hour)
		history.LimitWarningSent = limitWarningSent

		histories[userID] = history
	}

	err := l.userDB.EmailHistoriesSave(histories)
	if err != nil {
		return fmt.Errorf("save histories to DB: %w", err)
	}

	return nil
}

func (l *Limiter) filterOutStaleTimestamps(in []time.Time, delta time.Duration) (out []time.Time) {
	staleBefore := time.Now().Add(-delta)
	out = make([]time.Time, 0, len(in))

	for _, ts := range in {
		if ts.Before(staleBefore) {
			continue
		}
		out = append(out, ts)
	}

	return out
}
