// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package legacy

/*
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

// handleSetTOTP handles the setting of TOTP Key
func (p *LegacyPoliteiawww) handleSetTOTP(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleSetTOTP")

	var st www.SetTOTP
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&st); err != nil {
		RespondWithError(w, r, 0, "handleSetTOTP: unmarshal",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	u, err := p.sessions.GetSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleSetTOTP: getSessionUser %v", err)
		return
	}

	str, err := p.processSetTOTP(st, u)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleSetTOTP: processSetTOTP %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, str)
}

// handleVerifyTOTP handles the request to verify a set TOTP Key.
func (p *LegacyPoliteiawww) handleVerifyTOTP(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleVerifyTOTP")

	var vt www.VerifyTOTP
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&vt); err != nil {
		RespondWithError(w, r, 0, "handleVerifyTOTP: unmarshal",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	u, err := p.sessions.GetSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleVerifyTOTP: getSessionUser %v", err)
		return
	}

	vtr, err := p.processVerifyTOTP(vt, u)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleVerifyTOTP: processVerifyTOTP %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, vtr)
}
*/
