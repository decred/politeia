// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mail

import (
	"time"

	"github.com/decred/politeia/politeiawww/user"
	"github.com/google/uuid"
)

// Limiter wraps around client from the mail package and adds an email
// rate limit functionality for users.
type limiter struct {
	client     client
	userDB     user.Database
	limit      int
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
// of email addresses.
func (l *limiter) SendTo(subject, body string, recipients []string) error {
	return l.client.SendTo(subject, body, recipients)
}

// SendToUsers sends an email with the given subject and body to the provided list
// of email addresses. This adds an email rate limit functionality in order
// to avoid spamming from malicious users.
//
// This function satisfies the Mailer interface.
func (l *limiter) SendToUsers(subjects, body string, recipients []string) error {
	valid, invalid, histories, err := l.filterRecipients(recipients)
	if err != nil {
		return err
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
		err = l.client.SendTo(limitEmailSubject, limitEmailBody, invalid)
		if err != nil {
			return err
		}
	}

	// Update email histories on db.
	if len(histories) > 0 {
		l.userDB.EmailHistoriesSave(histories)
	}

	return nil
}

// filterRecipients divides recipients into valid, those that are able to
// receive emails, and invalid, those that have hit the email rate limit,
// but have not yet received the warning email. It also updates the email
// history for each user inside the recipients list.
func (l *limiter) filterRecipients(rs []string) ([]string, []string, map[uuid.UUID]user.EmailHistory, error) {
	// Sanity check
	if len(rs) == 0 {
		return nil, nil, nil, nil
	}

	// Compile user IDs from recipients and get their email histories.
	ids := make([]uuid.UUID, 0, len(rs))
	for _, email := range rs {
		ids = append(ids, l.userEmails[email])
	}
	hs, err := l.userDB.EmailHistoriesGet(ids)
	if err != nil {
		return nil, nil, nil, err
	}

	// Divide recipients into valid and invalid recipients, and parse their
	// new email history.
	var (
		valid     []string
		invalid   []string
		histories = make(map[uuid.UUID]user.EmailHistory, len(rs))
	)
	for _, email := range rs {
		id := l.userEmails[email]
		history, ok := hs[id]
		if !ok {
			// User does not have a mail history yet, add user to valid
			// recipients and create his email history.
			histories[id] = user.EmailHistory{
				Timestamps:       []int64{time.Now().Unix()},
				LimitWarningSent: false,
			}
			valid = append(valid, email)
			continue
		}

		// Filter timestamps for the past 24h.
		history.Timestamps = l.filterTimestamps(history.Timestamps,
			24*time.Hour)

		if len(history.Timestamps) >= l.limit {
			// Rate limit has been hit. If limit warning email has not yet
			// been sent, add user to invalid recipients and update email
			// history.
			if !history.LimitWarningSent {
				invalid = append(invalid, email)
				history.LimitWarningSent = true
				histories[id] = history
			}
			continue
		}

		// Rate limit has not been hit, add user to valid recipients and
		// update email history.
		valid = append(valid, email)
		history.Timestamps = append(history.Timestamps, time.Now().Unix())
		history.LimitWarningSent = false
		histories[id] = history
	}

	return valid, invalid, histories, nil
}

// filterTimestamps filters out timestamps from the passed in slice that comes
// before the specified delta time duration.
func (l *limiter) filterTimestamps(in []int64, delta time.Duration) []int64 {
	before := time.Now().Add(-delta)
	out := make([]int64, 0, len(in))

	for _, ts := range in {
		timestamp := time.Unix(ts, 0)
		if timestamp.Before(before) {
			continue
		}
		out = append(out, ts)
	}

	return out
}

// Limit warning email texts that are sent to invalid users.
const limitEmailSubject = "Email Rate Limit Hit"
const limitEmailBody = `
Your email rate limit for the past 24h has been hit. This measure is used to avoid malicious users spamming Politeia's email server. 
	
We apologize for any inconvenience.
`

// newLimiter returns a new limiter that implements the Mailer interface.
func newLimiter(c client, db user.Database, l int, ue map[string]uuid.UUID) *limiter {
	return &limiter{
		client:     c,
		userDB:     db,
		limit:      l,
		userEmails: ue,
	}
}
