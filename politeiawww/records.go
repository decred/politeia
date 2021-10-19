// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"net/http"

	v1 "github.com/decred/politeia/politeiawww/api/records/v1"
	"github.com/decred/politeia/util"
)

func (p *politeiawww) setupRecordRoutes() {
	p.addRoute(http.MethodPost, v1.APIRoute,
		v1.RoutePolicy, p.handleRecordsPolicy)
}

// handleRecordsPolicy is the request handler for the records v1 Policy route.
func (p *politeiawww) handleRecordsPolicy(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleRecordsPolicy")

	pr := v1.PolicyReply{
		RecordsPageSize:   v1.RecordsPageSize,
		InventoryPageSize: v1.InventoryPageSize,
	}

	util.RespondWithJSON(w, http.StatusOK, pr)
}
