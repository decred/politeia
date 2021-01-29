// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"encoding/json"
	"net/http"

	pdclient "github.com/decred/politeia/politeiad/client"
	v1 "github.com/decred/politeia/politeiawww/api/pi/v1"
	"github.com/decred/politeia/politeiawww/config"
	"github.com/decred/politeia/politeiawww/sessions"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/util"
)

// Pi is the context for the pi API.
type Pi struct {
	cfg       *config.Config
	politeiad *pdclient.Client
	userdb    user.Database
	sessions  *sessions.Sessions
}

// HandleProposals is the request handler for the pi v1 Proposals route.
func (p *Pi) HandleProposals(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandleProposals")

	var ps v1.Proposals
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&ps); err != nil {
		respondWithError(w, r, "HandleProposals: unmarshal",
			v1.UserErrorReply{
				ErrorCode: v1.ErrorCodeInputInvalid,
			})
		return
	}

	// Lookup session user. This is a public route so a session may not
	// exist. Ignore any session not found errors.
	u, err := p.sessions.GetSessionUser(w, r)
	if err != nil && err != sessions.ErrSessionNotFound {
		respondWithError(w, r,
			"HandleDetails: GetSessionUser: %v", err)
		return
	}

	psr, err := p.processProposals(r.Context(), ps, u)
	if err != nil {
		respondWithError(w, r,
			"HandleProposals: processProposals: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, psr)
}

// HandleVoteInventory is the request handler for the pi v1 VoteInventory
// route.
func (p *Pi) HandleVoteInventory(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandleVoteInventory")

	vir, err := p.processVoteInventory(r.Context())
	if err != nil {
		respondWithError(w, r,
			"HandleVoteInventory: processVoteInventory: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, vir)
}

// New returns a new Pi context.
func New(cfg *config.Config, pdc *pdclient.Client, s *sessions.Sessions, udb user.Database) *Pi {
	return &Pi{
		cfg:       cfg,
		politeiad: pdc,
		userdb:    udb,
		sessions:  s,
	}
}
