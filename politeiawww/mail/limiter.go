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

// Limiter is a wrapper around Mailer for implementing rate limiting
// functionality.
type Limiter struct {
	mailer Mailer
	userDB user.Database

	// limit defines max amount of emails a recipient can receive within last
	// 24h.
	limit int

	// emailHistoriesPageSize defines the page size that is used when querying
	// DB.
	emailHistoriesPageSize int
}

// NewLimiter returns new instance.
func NewLimiter(mailer Mailer, userDB user.Database, limit int) *Limiter {
	return &Limiter{
		mailer:                 mailer,
		userDB:                 userDB,
		limit:                  limit,
		emailHistoriesPageSize: user.EmailHistoriesPageLimit,
	}
}

// IsEnabled see mail.Mailer for details.
func (l *Limiter) IsEnabled() bool {
	return l.mailer.IsEnabled()
}

// SendTo see mail.Mailer for details.
func (l *Limiter) SendTo(subject, body string, recipients []string) error {
	return l.mailer.SendTo(subject, body, recipients)
}

// SendToUsers see mail.Mailer for details.
func (l *Limiter) SendToUsers(subject, body string, recipients map[uuid.UUID]string) error {
	page := make(map[uuid.UUID]string, l.emailHistoriesPageSize)

	// There might be a lot of recipients, handle them page by page.
	for userID, email := range recipients {
		if len(page) == l.emailHistoriesPageSize {
			err := l.sendToUsersPaginated(subject, body, page)
			if err != nil {
				return fmt.Errorf("send to users paginated: %w", err)
			}

			page = make(map[uuid.UUID]string, l.emailHistoriesPageSize)
		}

		page[userID] = email
	}

	return nil
}

func (l *Limiter) sendToUsersPaginated(subject, body string, recipients map[uuid.UUID]string) error {
	userIDs := make([]uuid.UUID, 0, len(recipients))
	for userID := range recipients {
		userIDs = append(userIDs, userID)
	}
	histories, err := l.userDB.EmailHistoriesGet(userIDs)
	if err != nil {
		return fmt.Errorf("fetch histories from DB: %w", err)
	}

	// Split recipients into two categories:
	// - good (those who won't hit rate limit)
	// - bad (those who will hit rate limit, according to the rules below)
	//
	// Also, keep track of their respective user.EmailHistory's in order to
	// adjust it and update accordingly to be relevant for the next
	// sendToUsersPaginated call.

	var (
		// Optimize for good recipients.
		good          = make([]string, 0, len(recipients))
		goodHistories = make(map[uuid.UUID]user.EmailHistory, len(recipients))
		bad           []string
		badHistories  = make(map[uuid.UUID]user.EmailHistory)
	)

	for userID, email := range recipients {
		history := histories[userID]
		// Some history entries might get irrelevant (if the fall out of 24h
		// window in the past), so we prune these entries here.
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

	// Handle good recipients if any.
	if len(good) > 0 {
		err = l.mailer.SendTo(subject, body, good)
		if err != nil {
			return fmt.Errorf("send mail: %w", err)
		}

		// Update histories meta-data in DB for these recipients.
		// Resetting limit warning to false to allow for sending a warning email
		// to these recipients in the next sendToUsersPaginated call if
		// necessary.
		err = l.refreshHistories(goodHistories, false)
		if err != nil {
			return fmt.Errorf("refresh histories: %w", err)
		}
	}

	// Handle bad recipients if any.
	if len(bad) > 0 {
		// Send a special "rate limit hit" email to bad recipients instead of
		// the intended one.
		// TODO
		// We'll need to define subject and body for a special "rate limit hit"
		// email here.
		rateLimitHitSubject := "TODO"
		rateLimitHitBody := "TODO"

		err = l.mailer.SendTo(rateLimitHitSubject, rateLimitHitBody, bad)
		if err != nil {
			return fmt.Errorf("send mail: %w", err)
		}

		// Update histories meta-data in DB for these recipients.
		// Setting limit warning to true to indicate that a warning email has
		// been sent to these recipients so that in the next call to
		// sendToUsersPaginated no duplicate warning email will be issued.
		err = l.refreshHistories(badHistories, true)
		if err != nil {
			return fmt.Errorf("refresh histories: %w", err)
		}
	}

	return nil
}

func (l *Limiter) refreshHistories(histories map[uuid.UUID]user.EmailHistory, limitWarningSent bool) error {
	for userID, history := range histories {
		history.SentTimestamps = append(history.SentTimestamps, time.Now().Unix())
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

func (l *Limiter) filterOutStaleTimestamps(in []int64, delta time.Duration) (out []int64) {
	staleBefore := time.Now().Add(-delta)
	out = make([]int64, 0, len(in))

	for _, ts := range in {
		timestamp := time.Unix(ts, 0)
		if timestamp.Before(staleBefore) {
			continue
		}
		out = append(out, ts)
	}

	return out
}
