// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package legacy

import (
	"net/http"
	"sync"

	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/politeia/politeiawww/config"
	"github.com/decred/politeia/politeiawww/mail"
	"github.com/decred/politeia/politeiawww/sessions"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// LegacyPoliteiawww represents the legacy politeiawww server.
type LegacyPoliteiawww struct {
	sync.RWMutex
	cfg      *config.Config
	params   *chaincfg.Params
	router   *mux.Router
	auth     *mux.Router // CSRF protected subrouter
	db       user.Database
	sessions *sessions.Sessions
	mail     mail.Mailer
	http     *http.Client

	// userEmails contains a mapping of all user emails to user ID.
	// This is required for now because the email is stored as part of
	// the encrypted user blob in the user database, but we also allow
	// the user to sign in using their email address, requiring a user
	// lookup by email. This is a temporary measure and should be
	// removed once all user by email lookups have been taken out.
	userEmails map[string]uuid.UUID // [email]userID

	// These fields are only used during piwww mode
	userPaywallPool map[uuid.UUID]paywallPoolMember // [userid][paywallPoolMember]

	// The following fields are only used during testing
	test bool
}

// NewLegacyPoliteiawww returns a new LegacyPoliteiawww.
func NewLegacyPoliteiawww(cfg *config.Config) *LegacyPoliteiawww {
	return &LegacyPoliteiawww{
		userEmails:      make(map[string]uuid.UUID, 1024),
		userPaywallPool: make(map[uuid.UUID]paywallPoolMember, 1024),
	}
}
