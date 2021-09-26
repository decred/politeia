// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package legacy

import (
	"encoding/json"
	"net/http"

	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/util"
)

// handleInviteNewUser handles the invitation of a new contractor by an
// administrator for the Contractor Management System.
func (p *LegacyPoliteiawww) handleInviteNewUser(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleInviteNewUser")

	// Get the new user command.
	var u cms.InviteNewUser
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&u); err != nil {
		RespondWithError(w, r, 0, "handleInviteNewUser: unmarshal", www.UserError{
			ErrorCode: www.ErrorStatusInvalidInput,
		})
		return
	}

	reply, err := p.processInviteNewUser(u)
	if err != nil {
		RespondWithError(w, r, 0, "handleInviteNewUser: ProcessInviteNewUser %v", err)
		return
	}

	// Reply with the verification token.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleRegisterUser handles the completion of registration by invited users of
// the Contractor Management System.
func (p *LegacyPoliteiawww) handleRegisterUser(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleRegisterUser")

	// Get the new user command.
	var u cms.RegisterUser
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&u); err != nil {
		RespondWithError(w, r, 0, "handleRegisterUser: unmarshal", www.UserError{
			ErrorCode: www.ErrorStatusInvalidInput,
		})
		return
	}

	reply, err := p.processRegisterUser(u)
	if err != nil {
		RespondWithError(w, r, 0, "handleRegisterUser: ProcessRegisterUser %v", err)
		return
	}

	// Reply with the verification token.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleCMSUsers handles fetching a list of cms users.
func (p *LegacyPoliteiawww) handleCMSUsers(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleCMSUsers")

	var cu cms.CMSUsers
	err := util.ParseGetParams(r, &cu)
	if err != nil {
		RespondWithError(w, r, 0, "handleCMSUsers: ParseGetParams",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	cur, err := p.processCMSUsers(&cu)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleCMSUsers: processCMSUsers %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, cur)
}
