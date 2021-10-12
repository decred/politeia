// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package legacy

import (
	"github.com/decred/politeia/politeiawww/legacy/user"
	"github.com/google/uuid"
)

// initUserEmailsCache initializes the userEmails cache by iterating through
// all the users in the database and adding a email-userID mapping for them.
//
// This function must be called WITHOUT the lock held.
func (p *Politeiawww) initUserEmailsCache() error {
	p.Lock()
	defer p.Unlock()

	return p.db.AllUsers(func(u *user.User) {
		p.userEmails[u.Email] = u.ID
	})
}

// setUserEmailsCache sets a email-userID mapping in the user emails cache.
//
// This function must be called WITHOUT the lock held.
func (p *Politeiawww) setUserEmailsCache(email string, id uuid.UUID) {
	p.Lock()
	defer p.Unlock()
	p.userEmails[email] = id
}

// userIDByEmail returns a userID given their email address.
//
// This function must be called WITHOUT the lock held.
func (p *Politeiawww) userIDByEmail(email string) (uuid.UUID, bool) {
	p.RLock()
	defer p.RUnlock()
	id, ok := p.userEmails[email]
	return id, ok
}

// userByEmail returns a User object given their email address.
//
// This function must be called WITHOUT the lock held.
func (p *Politeiawww) userByEmail(email string) (*user.User, error) {
	id, ok := p.userIDByEmail(email)
	if !ok {
		log.Debugf("userByEmail: email lookup failed for '%v'", email)
		return nil, user.ErrUserNotFound
	}
	return p.db.UserGetById(id)
}
