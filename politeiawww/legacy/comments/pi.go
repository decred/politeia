// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package comments

import (
	v1 "github.com/decred/politeia/politeiawww/api/comments/v1"
	"github.com/decred/politeia/politeiawww/legacy/user"
)

// paywallIsEnabled returns whether the user paywall is enabled.
//
// This function is a temporary function that will be removed once user plugins
// have been implemented.
func (c *Comments) paywallIsEnabled() bool {
	return c.cfg.PaywallAmount != 0 && c.cfg.PaywallXpub != ""
}

// userHasPaid returns whether the user has paid their user registration fee.
//
// This function is a temporary function that will be removed once user plugins
// have been implemented.
func userHasPaid(u user.User) bool {
	return u.NewUserPaywallTx != ""
}

// piHookNewPre hook runs before each New command.
func (c *Comments) piHookNewPre(u user.User) error {
	if !c.paywallIsEnabled() {
		return nil
	}

	// Verify user has paid registration paywall
	if !userHasPaid(u) {
		return v1.PluginErrorReply{
			PluginID:  user.PiUserPluginID,
			ErrorCode: user.ErrorCodeUserRegistrationNotPaid,
		}
	}

	return nil
}

// piHookEditPre hook runs before each Edit command.
func (c *Comments) piHookEditPre(u user.User) error {
	if !c.paywallIsEnabled() {
		return nil
	}

	// Verify user has paid registration paywall
	if !userHasPaid(u) {
		return v1.PluginErrorReply{
			PluginID:  user.PiUserPluginID,
			ErrorCode: user.ErrorCodeUserRegistrationNotPaid,
		}
	}

	return nil
}

// piHookVotePre hook runs before each Vote command.
func (c *Comments) piHookVotePre(u user.User) error {
	if !c.paywallIsEnabled() {
		return nil
	}

	// Verify user has paid registration paywall
	if !userHasPaid(u) {
		return v1.PluginErrorReply{
			PluginID:  user.PiUserPluginID,
			ErrorCode: user.ErrorCodeUserRegistrationNotPaid,
		}
	}

	return nil
}
