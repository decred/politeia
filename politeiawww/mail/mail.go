// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mail

import "github.com/google/uuid"

// Mailer provides an API for interacting with the smtp server.
type Mailer interface {
	// IsEnabled determines if the smtp server is enabled or not.
	IsEnabled() bool

	// SendTo sends an email to a list of recipient email addresses.
	// This function does not rate limit emails and a recipient does
	// does not need to correspond to a politeiawww user. This function
	// can be used to send emails to sysadmins or similar cases.
	SendTo(subject, body string, recipients []string) error

	// SendToUsers sends an email to a list of recipient email
	// addresses. The recipient MUST correspond to a politeiawww user
	// in the database for the email to be sent. This function rate
	// limits the number of emails that can be sent to any individual
	// user over a 24 hour period. If a recipient is provided that does
	// not correspond to a politeiawww user, the email is simply
	// skipped. An error is not returned.
	SendToUsers(subject, body string, recipients map[uuid.UUID]string) error
}
