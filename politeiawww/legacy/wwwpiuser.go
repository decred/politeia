// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package legacy

import (
	"encoding/json"
	"net/http"

	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/util"
)

// handleUserRegistrationPayment checks whether the provided transaction
// is on the blockchain and meets the requirements to consider the user
// registration fee as paid.
func (p *LegacyPoliteiawww) handleUserRegistrationPayment(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleUserRegistrationPayment")

	user, err := p.sessions.GetSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleUserRegistrationPayment: getSessionUser %v", err)
		return
	}

	vuptr, err := p.processUserRegistrationPayment(r.Context(), user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleUserRegistrationPayment: processUserRegistrationPayment %v",
			err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, vuptr)
}

// handleUserProposalPaywall returns paywall details that allows the user to
// purchase proposal credits.
func (p *LegacyPoliteiawww) handleUserProposalPaywall(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleUserProposalPaywall")

	user, err := p.sessions.GetSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleUserProposalPaywall: getSessionUser %v", err)
		return
	}

	reply, err := p.processUserProposalPaywall(user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleUserProposalPaywall: processUserProposalPaywall  %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleUserProposalPaywallTx returns the payment details for a pending
// proposal paywall payment.
func (p *LegacyPoliteiawww) handleUserProposalPaywallTx(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleUserProposalPaywallTx")

	user, err := p.sessions.GetSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleUserProposalPaywallTx: getSessionUser %v", err)
		return
	}

	reply, err := p.processUserProposalPaywallTx(user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleUserProposalPaywallTx: "+
				"processUserProposalPaywallTx %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleUserProposalCredits returns the spent and unspent proposal credits for
// the logged in user.
func (p *LegacyPoliteiawww) handleUserProposalCredits(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleUserProposalCredits")

	user, err := p.sessions.GetSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleUserProposalCredits: getSessionUser %v", err)
		return
	}

	reply, err := p.processUserProposalCredits(user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleUserProposalCredits: processUserProposalCredits  %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleUserPaymentsRescan allows an admin to rescan a user's paywall address
// to check for any payments that may have been missed by paywall polling.
func (p *LegacyPoliteiawww) handleUserPaymentsRescan(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleUserPaymentsRescan")

	var upr www.UserPaymentsRescan
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&upr); err != nil {
		RespondWithError(w, r, 0, "handleUserPaymentsRescan: unmarshal",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	reply, err := p.processUserPaymentsRescan(r.Context(), upr)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleUserPaymentsRescan: processUserPaymentsRescan:  %v",
			err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
}
