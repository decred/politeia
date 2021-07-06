// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mail

import (
	"github.com/decred/politeia/politeiawww/user"
	"github.com/google/uuid"
)

// Mailer is a simple interface used to send emails to a list of recipients.
// Any additional feature must come from the objects that implements it.
type Mailer interface {
	// IsEnabled determines if the smtp server is enabled or not.
	IsEnabled() bool

	// SendTo sends an email to a list of recipients email addresses.
	SendTo(subject, body string, recipients []string) error
}

// New returns a new mailer. The instantiated mailer depends on the passed in
// arguments.
func New(host, user, password, emailAddress, certPath string, skipVerify bool, limit int, db user.Database, userEmails map[string]uuid.UUID) (Mailer, error) {
	var mailer Mailer

	// Email is considered disabled if any of the required user
	// credentials are mising.
	if host == "" || user == "" || password == "" {
		log.Infof("Email: DISABLED")
		mailer = &client{
			disabled: true,
		}
		return mailer, nil
	}

	// Create a default client as the initial mailer.
	client, err := newClient(host, user, password, emailAddress, certPath,
		skipVerify)
	if err != nil {
		return nil, err
	}
	mailer = client

	// If rate limiting feature is enabled, wrap client with limiter
	// functionality.
	if limit != 0 {
		mailer = newLimiter(*client, db, limit, userEmails)
	}

	return mailer, nil
}
