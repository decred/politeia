// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package legacy

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/decred/politeia/politeiad/api/v1/mime"
	v1 "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/legacy/sessions"
	"github.com/decred/politeia/util"
	"github.com/decred/politeia/util/version"
	"github.com/gorilla/csrf"
)

// version is an HTTP GET to determine the lowest API route version that this
// backend supports.  Additionally it is used to obtain a CSRF token.
func (p *Politeiawww) handleVersion(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleVersion")

	versionReply := v1.VersionReply{
		Version:      v1.PoliteiaWWWAPIVersion,
		Route:        v1.PoliteiaWWWAPIRoute,
		BuildVersion: version.BuildMainVersion(),
		PubKey:       hex.EncodeToString(p.cfg.Identity.Key[:]),
		TestNet:      p.cfg.TestNet || p.cfg.SimNet,
		Mode:         p.cfg.Mode,
	}

	_, err := p.sessions.GetSessionUser(w, r)
	if err == nil {
		versionReply.ActiveUserSession = true
	}

	vr, err := json.Marshal(versionReply)
	if err != nil {
		RespondWithError(w, r, 0, "handleVersion: Marshal %v", err)
		return
	}

	w.Header().Set("Strict-Transport-Security",
		"max-age=63072000; includeSubDomains")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set(v1.CsrfToken, csrf.Token(r))

	w.WriteHeader(http.StatusOK)
	w.Write(vr)
}

func (p *Politeiawww) handlePolicy(w http.ResponseWriter, r *http.Request) {
	// Get the policy command.
	log.Tracef("handlePolicy")

	reply := &v1.PolicyReply{
		MinPasswordLength:          v1.PolicyMinPasswordLength,
		MinUsernameLength:          v1.PolicyMinUsernameLength,
		MaxUsernameLength:          v1.PolicyMaxUsernameLength,
		UsernameSupportedChars:     v1.PolicyUsernameSupportedChars,
		ProposalListPageSize:       v1.ProposalListPageSize,
		UserListPageSize:           v1.UserListPageSize,
		MaxImages:                  v1.PolicyMaxImages,
		MaxImageSize:               v1.PolicyMaxImageSize,
		MaxMDs:                     v1.PolicyMaxMDs,
		MaxMDSize:                  v1.PolicyMaxMDSize,
		PaywallEnabled:             p.paywallIsEnabled(),
		ValidMIMETypes:             mime.ValidMimeTypes(),
		MinProposalNameLength:      v1.PolicyMinProposalNameLength,
		MaxProposalNameLength:      v1.PolicyMaxProposalNameLength,
		ProposalNameSupportedChars: v1.PolicyProposalNameSupportedChars,
		MaxCommentLength:           v1.PolicyMaxCommentLength,
		TokenPrefixLength:          v1.TokenPrefixLength,
		BuildInformation:           version.BuildInformation(),
		IndexFilename:              v1.PolicyIndexFilename,
		MinLinkByPeriod:            0,
		MaxLinkByPeriod:            0,
		MinVoteDuration:            0,
		MaxVoteDuration:            0,
		PaywallConfirmations:       p.cfg.MinConfirmationsRequired,
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleUnauthenticatedWebsocket attempts to upgrade the current
// unauthenticated connection to a websocket connection.
func (p *Politeiawww) handleUnauthenticatedWebsocket(w http.ResponseWriter, r *http.Request) {
	// We are retrieving the uuid here to make sure it is NOT set. This
	// check looks backwards but is correct.
	id, err := p.sessions.GetSessionUserID(w, r)
	if err != nil && !errors.Is(err, sessions.ErrSessionNotFound) {
		http.Error(w, "Could not get session uuid",
			http.StatusBadRequest)
		return
	}
	if id != "" {
		http.Error(w, "Invalid session uuid", http.StatusBadRequest)
		return
	}
	log.Tracef("handleUnauthenticatedWebsocket: %v", id)
	defer log.Tracef("handleUnauthenticatedWebsocket exit: %v", id)

	p.ws.HandleWebsocket(w, r, id)
}

// handleAuthenticatedWebsocket attempts to upgrade the current authenticated
// connection to a websocket connection.
func (p *Politeiawww) handleAuthenticatedWebsocket(w http.ResponseWriter, r *http.Request) {
	id, err := p.sessions.GetSessionUserID(w, r)
	if err != nil {
		http.Error(w, "Could not get session uuid",
			http.StatusBadRequest)
		return
	}

	log.Tracef("handleAuthenticatedWebsocket: %v", id)
	defer log.Tracef("handleAuthenticatedWebsocket exit: %v", id)

	p.ws.HandleWebsocket(w, r, id)
}
