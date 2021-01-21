// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package comments

import (
	pdclient "github.com/decred/politeia/politeiad/client"
	"github.com/decred/politeia/politeiawww/config"
	"github.com/decred/politeia/politeiawww/events"
	"github.com/decred/politeia/politeiawww/sessions"
	"github.com/decred/politeia/politeiawww/user"
)

// Comments is the context for the comments API.
type Comments struct {
	cfg       *config.Config
	politeiad *pdclient.Client
	userdb    user.Database
	sessions  sessions.Sessions
	events    *events.Manager
}

// New returns a new Comments context.
func New(cfg *config.Config, politeiad *pdclient.Client, userdb user.Database) *Comments {
	return &Comments{
		cfg:       cfg,
		politeiad: politeiad,
		userdb:    userdb,
	}
}
