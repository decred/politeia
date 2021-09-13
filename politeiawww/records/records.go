// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package records

import (
	"net/http"

	pdclient "github.com/decred/politeia/politeiad/client"
	v1 "github.com/decred/politeia/politeiawww/api/records/v1"
	"github.com/decred/politeia/politeiawww/config"
	"github.com/decred/politeia/politeiawww/events"
	"github.com/decred/politeia/politeiawww/sessions"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/util"
)

// Records is the context for the records API.
type Records struct {
	cfg       *config.Config
	politeiad *pdclient.Client
	userdb    user.Database
	sessions  *sessions.Sessions
	events    *events.Manager
}

// HandleNew is the request handler for the records v1 New route.
func (c *Records) HandleNew(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandleNew")

	var n v1.New
	decoder := util.NewJSONDecoder(r.Body)
	if err := decoder.Decode(&n); err != nil {
		respondWithError(w, r, "HandleNew: unmarshal",
			v1.UserErrorReply{
				ErrorCode: v1.ErrorCodeInputInvalid,
			})
		return
	}

	u, err := c.sessions.GetSessionUser(w, r)
	if err != nil {
		respondWithError(w, r,
			"HandleNew: GetSessionUser: %v", err)
		return
	}

	nr, err := c.processNew(r.Context(), n, *u)
	if err != nil {
		respondWithError(w, r,
			"HandleNew: processNew: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, nr)
}

// HandleEdit is the request handler for the records v1 Edit route.
func (c *Records) HandleEdit(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandleEdit")

	var e v1.Edit
	decoder := util.NewJSONDecoder(r.Body)
	if err := decoder.Decode(&e); err != nil {
		respondWithError(w, r, "HandleEdit: unmarshal",
			v1.UserErrorReply{
				ErrorCode: v1.ErrorCodeInputInvalid,
			})
		return
	}

	u, err := c.sessions.GetSessionUser(w, r)
	if err != nil {
		respondWithError(w, r,
			"HandleEdit: GetSessionUser: %v", err)
		return
	}

	er, err := c.processEdit(r.Context(), e, *u)
	if err != nil {
		respondWithError(w, r,
			"HandleEdit: processEdit: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, er)
}

// HandleSetStatus is the request handler for the records v1 SetStatus route.
func (c *Records) HandleSetStatus(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandleSetStatus")

	var ss v1.SetStatus
	decoder := util.NewJSONDecoder(r.Body)
	if err := decoder.Decode(&ss); err != nil {
		respondWithError(w, r, "HandleSetStatus: unmarshal",
			v1.UserErrorReply{
				ErrorCode: v1.ErrorCodeInputInvalid,
			})
		return
	}

	u, err := c.sessions.GetSessionUser(w, r)
	if err != nil {
		respondWithError(w, r,
			"HandleSetStatus: GetSessionUser: %v", err)
		return
	}

	ssr, err := c.processSetStatus(r.Context(), ss, *u)
	if err != nil {
		respondWithError(w, r,
			"HandleSetStatus: processSetStatus: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, ssr)
}

// HandleDetails is the request handler for the records v1 Details route.
func (c *Records) HandleDetails(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandleDetails")

	var d v1.Details
	decoder := util.NewJSONDecoder(r.Body)
	if err := decoder.Decode(&d); err != nil {
		respondWithError(w, r, "HandleDetails: unmarshal",
			v1.UserErrorReply{
				ErrorCode: v1.ErrorCodeInputInvalid,
			})
		return
	}

	// Lookup session user. This is a public route so a session may not
	// exist. Ignore any session not found errors.
	u, err := c.sessions.GetSessionUser(w, r)
	if err != nil && err != sessions.ErrSessionNotFound {
		respondWithError(w, r,
			"HandleDetails: GetSessionUser: %v", err)
		return
	}

	dr, err := c.processDetails(r.Context(), d, u)
	if err != nil {
		respondWithError(w, r,
			"HandleDetails: processDetails: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, dr)
}

// HandleTimestamps is the request handler for the records v1 Timestamps route.
func (c *Records) HandleTimestamps(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandleTimestamps")

	var t v1.Timestamps
	decoder := util.NewJSONDecoder(r.Body)
	if err := decoder.Decode(&t); err != nil {
		respondWithError(w, r, "HandleTimestamps: unmarshal",
			v1.UserErrorReply{
				ErrorCode: v1.ErrorCodeInputInvalid,
			})
		return
	}

	// Lookup session user. This is a public route so a session may not
	// exist. Ignore any session not found errors.
	u, err := c.sessions.GetSessionUser(w, r)
	if err != nil && err != sessions.ErrSessionNotFound {
		respondWithError(w, r,
			"HandleTimestamps: getSessionUser: %v", err)
		return
	}

	isAdmin := u != nil && u.Admin
	tr, err := c.processTimestamps(r.Context(), t, isAdmin)
	if err != nil {
		respondWithError(w, r,
			"HandleTimestamps: processTimestamps: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, tr)
}

// HandleRecords is the request handler for the records v1 Records route.
func (c *Records) HandleRecords(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandleRecords")

	var rs v1.Records
	decoder := util.NewJSONDecoder(r.Body)
	if err := decoder.Decode(&rs); err != nil {
		respondWithError(w, r, "HandleRecords: unmarshal",
			v1.UserErrorReply{
				ErrorCode: v1.ErrorCodeInputInvalid,
			})
		return
	}

	// Lookup session user. This is a public route so a session may not
	// exist. Ignore any session not found errors.
	u, err := c.sessions.GetSessionUser(w, r)
	if err != nil && err != sessions.ErrSessionNotFound {
		respondWithError(w, r,
			"HandleRecords: GetSessionUser: %v", err)
		return
	}

	rsr, err := c.processRecords(r.Context(), rs, u)
	if err != nil {
		respondWithError(w, r,
			"HandleRecords: processRecords: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, rsr)
}

// HandleInventory is the request handler for the records v1 Inventory route.
func (c *Records) HandleInventory(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandleInventory")

	var i v1.Inventory
	decoder := util.NewJSONDecoder(r.Body)
	if err := decoder.Decode(&i); err != nil {
		respondWithError(w, r, "HandleInventory: unmarshal",
			v1.UserErrorReply{
				ErrorCode: v1.ErrorCodeInputInvalid,
			})
		return
	}

	// Lookup session user. This is a public route so a session may not
	// exist. Ignore any session not found errors.
	u, err := c.sessions.GetSessionUser(w, r)
	if err != nil && err != sessions.ErrSessionNotFound {
		respondWithError(w, r,
			"HandleInventory: GetSessionUser: %v", err)
		return
	}

	ir, err := c.processInventory(r.Context(), i, u)
	if err != nil {
		respondWithError(w, r,
			"HandleInventory: processInventory: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, ir)
}

// HandleInventoryOrdered is the request handler for the records v1
// InventoryOrdered route.
func (c *Records) HandleInventoryOrdered(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandleInventoryOrdered")

	var i v1.InventoryOrdered
	decoder := util.NewJSONDecoder(r.Body)
	if err := decoder.Decode(&i); err != nil {
		respondWithError(w, r, "HandleInventoryOrdered: unmarshal",
			v1.UserErrorReply{
				ErrorCode: v1.ErrorCodeInputInvalid,
			})
		return
	}

	// Lookup session user. This is a public route so a session may not
	// exist. Ignore any session not found errors.
	u, err := c.sessions.GetSessionUser(w, r)
	if err != nil && err != sessions.ErrSessionNotFound {
		respondWithError(w, r,
			"HandleInventoryOrdered: GetSessionUser: %v", err)
		return
	}

	ir, err := c.processInventoryOrdered(r.Context(), i, u)
	if err != nil {
		respondWithError(w, r,
			"HandleInventoryOrdered: processInventoryOrdered: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, ir)
}

// HandleUserRecords is the request handler for the records v1 UserRecords
// route.
func (c *Records) HandleUserRecords(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandleUserRecords")

	var ur v1.UserRecords
	decoder := util.NewJSONDecoder(r.Body)
	if err := decoder.Decode(&ur); err != nil {
		respondWithError(w, r, "HandleUserRecords: unmaurhal",
			v1.UserErrorReply{
				ErrorCode: v1.ErrorCodeInputInvalid,
			})
		return
	}

	// Lookup session user. This is a public route so a session may not
	// exist. Ignore any session not found errour.
	u, err := c.sessions.GetSessionUser(w, r)
	if err != nil && err != sessions.ErrSessionNotFound {
		respondWithError(w, r,
			"HandleUserRecords: GetSessionUser: %v", err)
		return
	}

	urr, err := c.processUserRecords(r.Context(), ur, u)
	if err != nil {
		respondWithError(w, r,
			"HandleUserRecords: processsUserRecords: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, urr)
}

// New returns a new Records context.
func New(cfg *config.Config, pdc *pdclient.Client, udb user.Database, s *sessions.Sessions, e *events.Manager) *Records {
	return &Records{
		cfg:       cfg,
		politeiad: pdc,
		userdb:    udb,
		sessions:  s,
		events:    e,
	}
}
