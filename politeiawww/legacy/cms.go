// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package legacy

/*
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
*/
