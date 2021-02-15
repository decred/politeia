// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package records

import (
	"fmt"

	v1 "github.com/decred/politeia/politeiawww/api/records/v1"
	"github.com/decred/politeia/politeiawww/pi"
	"github.com/decred/politeia/politeiawww/user"
)

// paywallIsEnabled returns whether the user paywall is enabled.
//
// This function is a temporary function that will be removed once user plugins
// have been implemented.
func (r *Records) paywallIsEnabled() bool {
	return r.cfg.PaywallAmount != 0 && r.cfg.PaywallXpub != ""
}

// userHasPaid returns whether the user has paid their user registration fee.
//
// This function is a temporary function that will be removed once user plugins
// have been implemented.
func userHasPaid(u user.User) bool {
	return u.NewUserPaywallTx != ""
}

// userHashProposalCredits returns whether the user has any unspent proposal
// credits.
//
// This function is a temporary function that will be removed once user plugins
// have been implemented.
func userHasProposalCredits(u user.User) bool {
	return len(u.UnspentProposalCredits) > 0
}

// spendProposalCredit moves a unspent credit to the spent credit list and
// updates the user in the database.
//
// This function is a temporary function that will be removed once user plugins
// have been implemented.
func (r *Records) spendProposalCredit(u user.User, token string) error {
	// Verify there are credits to be spent
	if !userHasProposalCredits(u) {
		return fmt.Errorf("no proposal credits found")
	}

	// Credits are spent FIFO
	c := u.UnspentProposalCredits[0]
	c.CensorshipToken = token
	u.SpentProposalCredits = append(u.SpentProposalCredits, c)
	u.UnspentProposalCredits = u.UnspentProposalCredits[1:]

	return r.userdb.UserUpdate(u)
}

// piHookNewRecordpre executes the new record pre hook for pi.
//
// This function is a temporary function that will be removed once user plugins
// have been implemented.
func (r *Records) piHookNewRecordPre(u user.User) error {
	if !r.paywallIsEnabled() {
		return nil
	}

	// Verify user has paid registration paywall
	if !userHasPaid(u) {
		return v1.PluginErrorReply{
			PluginID:  pi.UserPluginID,
			ErrorCode: pi.ErrorCodeUserRegistrationNotPaid,
		}
	}

	// Verify user has a proposal credit
	if !userHasProposalCredits(u) {
		return v1.PluginErrorReply{
			PluginID:  pi.UserPluginID,
			ErrorCode: pi.ErrorCodeUserBalanceInsufficient,
		}
	}
	return nil
}

// piHoonNewRecordPost executes the new record post hook for pi.
//
// This function is a temporary function that will be removed once user plugins
// have been implemented.
func (r *Records) piHookNewRecordPost(u user.User, token string) error {
	if !r.paywallIsEnabled() {
		return nil
	}
	return r.spendProposalCredit(u, token)
}
