// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"net/http"
	"sync"

	"github.com/decred/dcrd/chaincfg/v3"
	pdclient "github.com/decred/politeia/politeiad/client"
	"github.com/decred/politeia/politeiawww/cmsdatabase"
	"github.com/decred/politeia/politeiawww/codetracker"
	"github.com/decred/politeia/politeiawww/config"
	"github.com/decred/politeia/politeiawww/events"
	"github.com/decred/politeia/politeiawww/mail"
	"github.com/decred/politeia/politeiawww/sessions"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/wsdcrdata"
	"github.com/gorilla/mux"
	"github.com/robfig/cron"
)

// TODO remove all unused fields
// politeiawww represents the politeiawww server.
type politeiawww struct {
	sync.RWMutex
	cfg       *config.Config
	params    *chaincfg.Params
	router    *mux.Router
	auth      *mux.Router // CSRF protected subrouter
	politeiad *pdclient.Client
	http      *http.Client // Deprecated; use politeiad client
	db        user.Database
	mail      mail.Mailer
	sessions  *sessions.Sessions
	events    *events.Manager

	// Client websocket connections
	ws    map[string]map[string]*wsContext // [uuid][]*context
	wsMtx sync.RWMutex

	// These fields are use only during cmswww mode
	cmsDB     cmsdatabase.Database
	cron      *cron.Cron
	wsDcrdata *wsdcrdata.Client
	tracker   codetracker.CodeTracker
}
