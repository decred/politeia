// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mail

import (
	"github.com/decred/politeia/politeiawww/user"
	"github.com/google/uuid"
)

// Mailer is an interface used to send emails to a list of recipients.
type Mailer interface {
	// IsEnabled determines if the smtp server is enabled or not.
	IsEnabled() bool

	// SendTo sends an email to a list of recipients email addresses. This
	// function does not limit emails, and is used to send email to sysadmins
	// or similar operations.
	SendTo(subject, body string, recipients []string) error

	// SendToUsers sends an email to a list of recipients email addresses. This
	// function rate limits the amount of emails a www user can receive in a
	// specific time window.
	SendToUsers(subject, body string, recipients []string) error
}

// New returns a new mailer.
func New(host, user, password, emailAddress, certPath string, skipVerify bool, limit int, db user.Database, userEmails map[string]uuid.UUID) (Mailer, error) {
	var mailer Mailer

	// Email is considered disabled if any of the required user
	// credentials are mising.
	if host == "" || user == "" || password == "" {
		log.Infof("Mail: DISABLED")
		c := &client{
			disabled: true,
		}
		mailer = &limiter{
			client: *c,
			userDB: db,
		}
		return mailer, nil
	}

	// Create a new smtp client.
	client, err := newClient(host, user, password, emailAddress, certPath,
		skipVerify)
	if err != nil {
		return nil, err
	}

	// Create a new mailer with rate limiting functionality.
	mailer = newLimiter(*client, db, limit, userEmails)

	return mailer, nil
}
