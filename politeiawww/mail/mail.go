// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mail

import (
	"github.com/decred/politeia/politeiawww/user"
)

// Mailer is an interface used to send emails to a list of recipients.
type Mailer interface {
	// IsEnabled determines if the smtp server is enabled or not.
	IsEnabled() bool

	// SendTo sends an email to a list of recipients email addresses. This
	// function does not limit emails, and is used to send email to sysadmins
	// or similar cases.
	SendTo(subject, body string, recipients []string) error

	// SendToUsers sends an email to a list of recipients email addresses. This
	// function rate limits the amount of emails a www user can receive in a
	// specific time window.
	SendToUsers(subject, body string, recipients []string) error
}

// New returns a new client that implements Mailer.
func New(host, user, password, emailAddress, certPath string, skipVerify bool, limit int, db user.MailerDB) (*client, error) {
	// Email is considered disabled if any of the required user
	// credentials are missing.
	if host == "" || user == "" || password == "" {
		log.Infof("Mail: DISABLED")
		c := &client{
			disabled: true,
			mailerDB: db,
		}
		return c, nil
	}

	// Return a new mailer smtp client.
	return newClient(host, user, password, emailAddress, certPath,
		skipVerify, db, limit)
}
