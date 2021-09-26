// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"os"
	"time"

	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/user"
)

// _logAdminAction logs a string to the admin log file.
//
// This function must be called WITH the mutex held.
func (p *LegacyPoliteiawww) _logAdminAction(adminUser *user.User, content string) error {
	if p.test {
		return nil
	}

	f, err := os.OpenFile(p.cfg.AdminLogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0640)
	if err != nil {
		return err
	}
	defer f.Close()

	dateTimeStr := time.Now().UTC().Format("2006-01-02 15:04:05")
	_, err = fmt.Fprintf(f, "%v,%v,%v,%v\n", dateTimeStr,
		adminUser.ID, adminUser.Username, content)
	return err
}

// logAdminAction logs a string to the admin log file.
//
// This function must be called WITHOUT the mutex held.
func (p *LegacyPoliteiawww) logAdminAction(adminUser *user.User, content string) error {
	p.Lock()
	defer p.Unlock()

	return p._logAdminAction(adminUser, content)
}

// logAdminUserAction logs an admin action on a specific user.
//
// This function must be called WITHOUT the mutex held.
func (p *LegacyPoliteiawww) logAdminUserAction(adminUser, user *user.User, action www.UserManageActionT, reasonForAction string) error {
	return p.logAdminAction(adminUser, fmt.Sprintf("%v,%v,%v,%v",
		www.UserManageAction[action], user.ID, user.Username, reasonForAction))
}

// logAdminProposalAction logs an admin action on a proposal.
//
// This function must be called WITHOUT the mutex held.
func (p *LegacyPoliteiawww) logAdminProposalAction(adminUser *user.User, token, action, reason string) error {
	return p.logAdminAction(adminUser, fmt.Sprintf("%v,%v,%v", action, token, reason))
}
