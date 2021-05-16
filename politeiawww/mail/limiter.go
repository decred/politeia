// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mail

import (
	"fmt"

	"github.com/decred/politeia/politeiawww/user"
)

// Limiter is a wrapper around Mailer for implementing rate limiting functionality.
type Limiter struct {
	mailer Mailer
	userDB user.Database
	// limit24h defines max amount of emails a recipient can receive within last 24h.
	limit24h int
}

func NewLimiter(mailer Mailer, userDB user.Database, limit24h int) *Limiter {
	return &Limiter{
		mailer:   mailer,
		userDB:   userDB,
		limit24h: limit24h,
	}
}

// IsEnabled returns whether the mail server is enabled.
func (l *Limiter) IsEnabled() bool {
	return l.mailer.IsEnabled()
}

// SendTo splits recipients in two groups: good and bad. Bad recipients are
// those who will hit pre-configured rate limit, they will receive a special
// warning email, but only if they haven't received one already.
// Good recipients won't hit rate limit, they will receive the original message
// as is specified by subject and body arguments.
func (l *Limiter) SendTo(subject, body string, recipients []string) error {
	histories, err := l.userDB.FetchHistories24h(recipients)
	if err != nil {
		return fmt.Errorf("fetch histories from DB: %w", err)
	}

	var (
		// Optimize for good recipients (those who won't hit rate limit).
		good          = make([]string, 0, len(recipients))
		goodHistories = make([]user.EmailHistory24h, 0, len(recipients))
		bad           []string
		badHistories  []user.EmailHistory24h
	)

	for _, recipient := range recipients {
		history, ok := l.findHistory(recipient, histories)
		if !ok {
			// No previous history, no rate limiting is necessary.
			good = append(good, recipient)
			goodHistories = append(goodHistories, user.EmailHistory24h{
				Email: recipient,
			})
			continue
		}
		if len(history.SentTimestamps24h) < l.limit24h {
			// Previous history is fine, no rate limiting is necessary.
			good = append(good, recipient)
			goodHistories = append(goodHistories, history)
			continue
		}
		if history.LimitWarningSent {
			// Rate limit is hit, but warning message has already been sent.
			continue
		}
		// Rate limit is hit.
		bad = append(bad, recipient)
		badHistories = append(badHistories, history)
	}

	if len(good) > 0 {
		err = l.mailer.SendTo(subject, body, good)
		if err != nil {
			return fmt.Errorf("send mail: %w", err)
		}
		err = l.userDB.RefreshHistories24h(goodHistories, false)
		if err != nil {
			return fmt.Errorf("refresh histories in DB: %w", err)
		}
	}

	if len(bad) > 0 {
		err = l.mailer.SendTo(subject, body, bad)
		if err != nil {
			return fmt.Errorf("send mail: %w", err)
		}
		err = l.userDB.RefreshHistories24h(badHistories, true)
		if err != nil {
			return fmt.Errorf("refresh histories in DB: %w", err)
		}
	}

	return nil
}

func (l *Limiter) findHistory(recipient string, histories []user.EmailHistory24h) (user.EmailHistory24h, bool) {
	// This assumes histories slice is pretty small to iterate it in O(n).
	for _, history := range histories {
		if history.Email == recipient {
			return history, true
		}
	}
	return user.EmailHistory24h{}, false
}
