// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mail

import (
	"github.com/decred/politeia/politeiawww/user"
	"github.com/google/uuid"
)

// Mailer is agnostic to the notion of politeiawww users, and functionality
// that involves them must come from different Mailer wrappers who implement
// it.
type Mailer interface {
	// IsEnabled determines if the smtp server is enabled or not
	IsEnabled() bool

	// SendTo sends an email to a list of recipients email addresses. This
	// function is agnostic to the concept of www users.
	SendTo(subject, body string, recipients []string) error
}

// New returns a new mailer. Can instantiate a default client or a limiter client.
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

	// Create default client as our initial mailer
	client, err := newClient(host, user, password, emailAddress, certPath, skipVerify)
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
