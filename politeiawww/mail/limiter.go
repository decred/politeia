// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mail

import (
	"github.com/decred/politeia/politeiawww/user"
)

// Limiter wraps around Client from the mail package and adds a
// email rate limit functionality for users.
type limiter struct {
	client client
	userDB user.Database
	limit  int
}

var (
	_ Mailer = (*limiter)(nil)
)

func (l *limiter) IsEnabled() bool {
	return l.client.disabled
}

// use sendToLimited for rate limiting functionality
func (l *limiter) SendTo(subjects, body string, recipients []string) error {
	return l.client.SendTo(subjects, body, recipients)
}

// client.SendTo will be used here actually
func (l *limiter) sendToLimited(subjects, body, users []string) error {
	return nil
}

func newLimiter(c client, db user.Database, l int) *limiter {
	return &limiter{
		client: c,
		userDB: db,
		limit:  l,
	}
}
