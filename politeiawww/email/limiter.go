// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package email

import (
	"time"

	"github.com/decred/politeia/politeiawww/user"
)

type Limiter struct {
	mailer mailer
	userDB user.Database
	// limit24h defines max amount of emails a recipient can receive within last 24h.
	limit24h int
	timeFn   func() time.Time
}

func NewLimiter(mailer mailer, userDB user.Database, limit24h int, timeFn func() time.Time) *Limiter {
	return &Limiter{
		mailer:   mailer,
		userDB:   userDB,
		limit24h: limit24h,
		timeFn:   timeFn,
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
	histories, err := l.userDB.FetchHistories(recipients)
	if err != nil {
		// TODO
	}

	var (
		// Optimize for good recipients (those who won't hit rate limit).
		good = make([]string, 0, len(recipients))
		bad  []string
	)

	for _, recipient := range recipients {
		history, ok := l.findHistory(recipient, histories)
		if !ok || history.SentCount24h < l.limit24h {
			// No rate limiting is necessary.
			good = append(good, recipient)
			continue
		}
		if history.LimitWarningSent {
			// Rate limit is hit, but warning message has already been sent.
			continue
		}
		// Rate limit is hit.
		bad = append(bad, recipient)
	}

	timestamp := l.timeFn()

	err = l.mailer.SendTo(subject, body, good)
	if err != nil {
		// TODO
	}
	err = l.userDB.RefreshHistories(good, false, timestamp)
	if err != nil {
		// TODO
	}

	err = l.mailer.SendTo(subject, body, bad)
	if err != nil {
		// TODO
	}
	err = l.userDB.RefreshHistories(good, true, timestamp)
	if err != nil {
		// TODO
	}

	return nil
}

func (l *Limiter) findHistory(recipient string, histories []user.EmailHistory) (user.EmailHistory, bool) {
	// This assumes histories slice is pretty small to iterate it in O(n).
	for _, history := range histories {
		if history.Email == recipient {
			return history, true
		}
	}
	return user.EmailHistory{}, false
}

type mailer interface {
	IsEnabled() bool
	SendTo(subject, body string, recipients []string) error
}
