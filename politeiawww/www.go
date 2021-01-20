// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"context"
	"crypto/elliptic"
	"crypto/tls"
	_ "encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/decred/politeia/mdstream"
	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/plugins/comments"
	piplugin "github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	pi "github.com/decred/politeia/politeiawww/api/pi/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	database "github.com/decred/politeia/politeiawww/cmsdatabase"
	cmsdb "github.com/decred/politeia/politeiawww/cmsdatabase/cockroachdb"
	ghtracker "github.com/decred/politeia/politeiawww/codetracker/github"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/politeiawww/user/cockroachdb"
	"github.com/decred/politeia/politeiawww/user/localdb"
	"github.com/decred/politeia/util"
	"github.com/decred/politeia/util/version"
	"github.com/decred/politeia/wsdcrdata"
	"github.com/google/uuid"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"github.com/robfig/cron"
)

type permission uint

const (
	permissionPublic permission = iota
	permissionLogin
	permissionAdmin

	csrfKeyLength = 32
)

func convertWWWErrorStatusFromPD(e pd.ErrorStatusT) www.ErrorStatusT {
	switch e {
	case pd.ErrorStatusInvalidRequestPayload:
		// Intentionally omitted because this indicates a politeiawww
		// server error so a ErrorStatusInvalid should be returned.
	case pd.ErrorStatusInvalidChallenge:
		// Intentionally omitted because this indicates a politeiawww
		// server error so a ErrorStatusInvalid should be returned.
	case pd.ErrorStatusInvalidFilename:
		return www.ErrorStatusInvalidFilename
	case pd.ErrorStatusInvalidFileDigest:
		return www.ErrorStatusInvalidFileDigest
	case pd.ErrorStatusInvalidBase64:
		return www.ErrorStatusInvalidBase64
	case pd.ErrorStatusInvalidMIMEType:
		return www.ErrorStatusInvalidMIMEType
	case pd.ErrorStatusUnsupportedMIMEType:
		return www.ErrorStatusUnsupportedMIMEType
	case pd.ErrorStatusInvalidRecordStatusTransition:
		return www.ErrorStatusInvalidPropStatusTransition
	case pd.ErrorStatusRecordNotFound:
		return www.ErrorStatusProposalNotFound
	}
	return www.ErrorStatusInvalid
}

// TODO verify all plugin errors have been added to these www conversion
// functions
func convertWWWErrorStatusFromPiPlugin(e piplugin.ErrorCodeT) www.ErrorStatusT {
	return www.ErrorStatusInvalid
}

func convertWWWErrorStatusFromComments(e comments.ErrorCodeT) www.ErrorStatusT {
	switch e {
	case comments.ErrorCodeTokenInvalid:
		return www.ErrorStatusInvalidCensorshipToken
	case comments.ErrorCodeCommentNotFound:
		return www.ErrorStatusCommentNotFound
	case comments.ErrorCodeParentIDInvalid:
		return www.ErrorStatusCommentNotFound
	}
	return www.ErrorStatusInvalid
}

func convertWWWErrorStatusFromTicketVote(e ticketvote.ErrorCodeT) www.ErrorStatusT {
	switch e {
	case ticketvote.ErrorCodeTokenInvalid:
		return www.ErrorStatusInvalidCensorshipToken
	case ticketvote.ErrorCodePublicKeyInvalid:
		return www.ErrorStatusInvalidPublicKey
	case ticketvote.ErrorCodeSignatureInvalid:
		return www.ErrorStatusInvalidSignature
	case ticketvote.ErrorCodeRecordStatusInvalid:
		return www.ErrorStatusWrongStatus
	case ticketvote.ErrorCodeVoteParamsInvalid:
		return www.ErrorStatusInvalidPropVoteParams
	case ticketvote.ErrorCodeVoteStatusInvalid:
		return www.ErrorStatusInvalidPropVoteStatus
	}
	return www.ErrorStatusInvalid
}

// convertWWWErrorStatus attempts to convert the provided politeiad plugin ID
// and error code into a www ErrorStatusT. If a plugin ID is provided the error
// code is assumed to be a user error code from the specified plugin API.  If
// no plugin ID is provided the error code is assumed to be a user error code
// from the politeiad API.
func convertWWWErrorStatus(pluginID string, errCode int) www.ErrorStatusT {
	switch pluginID {
	case "":
		// politeiad API
		e := pd.ErrorStatusT(errCode)
		return convertWWWErrorStatusFromPD(e)
	case piplugin.ID:
		// Pi plugin
		e := piplugin.ErrorCodeT(errCode)
		return convertWWWErrorStatusFromPiPlugin(e)
	case comments.ID:
		// Comments plugin
		e := comments.ErrorCodeT(errCode)
		return convertWWWErrorStatusFromComments(e)
	case ticketvote.ID:
		// Ticket vote plugin
		e := ticketvote.ErrorCodeT(errCode)
		return convertWWWErrorStatusFromTicketVote(e)
	}

	// No corresponding www error status found
	return www.ErrorStatusInvalid
}

func convertPiErrorStatusFromPD(e pd.ErrorStatusT) pi.ErrorStatusT {
	switch e {
	case pd.ErrorStatusInvalidRequestPayload:
		// Intentionally omitted because this indicates a politeiawww
		// server error so a ErrorStatusInvalid should be returned.
	case pd.ErrorStatusInvalidChallenge:
		// Intentionally omitted because this indicates a politeiawww
		// server error so a ErrorStatusInvalid should be returned.
	case pd.ErrorStatusInvalidFilename:
		return pi.ErrorStatusFileNameInvalid
	case pd.ErrorStatusInvalidFileDigest:
		return pi.ErrorStatusFileDigestInvalid
	case pd.ErrorStatusInvalidBase64:
		return pi.ErrorStatusFilePayloadInvalid
	case pd.ErrorStatusInvalidMIMEType:
		return pi.ErrorStatusFileMIMEInvalid
	case pd.ErrorStatusUnsupportedMIMEType:
		return pi.ErrorStatusFileMIMEInvalid
	case pd.ErrorStatusInvalidRecordStatusTransition:
		return pi.ErrorStatusPropStatusChangeInvalid
	case pd.ErrorStatusNoChanges:
		return pi.ErrorStatusNoPropChanges
	case pd.ErrorStatusRecordNotFound:
		return pi.ErrorStatusPropNotFound
	case pd.ErrorStatusInvalidToken:
		return pi.ErrorStatusPropTokenInvalid
	}
	return pi.ErrorStatusInvalid
}

func convertPiErrorStatusFromPiPlugin(e piplugin.ErrorCodeT) pi.ErrorStatusT {
	switch e {
	case piplugin.ErrorCodePageSizeExceeded:
		return pi.ErrorStatusPageSizeExceeded
	case piplugin.ErrorCodePropTokenInvalid:
		return pi.ErrorStatusPropTokenInvalid
	case piplugin.ErrorCodePropStatusInvalid:
		return pi.ErrorStatusPropStatusInvalid
	case piplugin.ErrorCodePropVersionInvalid:
		return pi.ErrorStatusPropVersionInvalid
	case piplugin.ErrorCodePropStatusChangeInvalid:
		return pi.ErrorStatusPropStatusChangeInvalid
	case piplugin.ErrorCodePropLinkToInvalid:
		return pi.ErrorStatusPropLinkToInvalid
	case piplugin.ErrorCodeVoteStatusInvalid:
		return pi.ErrorStatusVoteStatusInvalid
	case piplugin.ErrorCodeStartDetailsInvalid:
		return pi.ErrorStatusStartDetailsInvalid
	case piplugin.ErrorCodeStartDetailsMissing:
		return pi.ErrorStatusStartDetailsMissing
	case piplugin.ErrorCodeVoteParentInvalid:
		return pi.ErroStatusVoteParentInvalid
	}
	return pi.ErrorStatusInvalid
}

func convertPiErrorStatusFromComments(e comments.ErrorCodeT) pi.ErrorStatusT {
	switch e {
	case comments.ErrorCodeTokenInvalid:
		return pi.ErrorStatusPropTokenInvalid
	case comments.ErrorCodePublicKeyInvalid:
		return pi.ErrorStatusPublicKeyInvalid
	case comments.ErrorCodeSignatureInvalid:
		return pi.ErrorStatusSignatureInvalid
	case comments.ErrorCodeCommentTextInvalid:
		return pi.ErrorStatusCommentTextInvalid
	case comments.ErrorCodeCommentNotFound:
		return pi.ErrorStatusCommentNotFound
	case comments.ErrorCodeUserUnauthorized:
		return pi.ErrorStatusUnauthorized
	case comments.ErrorCodeParentIDInvalid:
		return pi.ErrorStatusCommentParentIDInvalid
	case comments.ErrorCodeVoteInvalid:
		return pi.ErrorStatusCommentVoteInvalid
	case comments.ErrorCodeVoteChangesMax:
		return pi.ErrorStatusCommentVoteChangesMax
	}
	return pi.ErrorStatusInvalid
}

func convertPiErrorStatusFromTicketVote(e ticketvote.ErrorCodeT) pi.ErrorStatusT {
	switch e {
	case ticketvote.ErrorCodeTokenInvalid:
		return pi.ErrorStatusPropTokenInvalid
	case ticketvote.ErrorCodePublicKeyInvalid:
		return pi.ErrorStatusPublicKeyInvalid
	case ticketvote.ErrorCodeSignatureInvalid:
		return pi.ErrorStatusSignatureInvalid
	case ticketvote.ErrorCodeRecordStatusInvalid:
		return pi.ErrorStatusPropStatusInvalid
	case ticketvote.ErrorCodeAuthorizationInvalid:
		return pi.ErrorStatusVoteAuthInvalid
	case ticketvote.ErrorCodeVoteParamsInvalid:
		return pi.ErrorStatusVoteParamsInvalid
	case ticketvote.ErrorCodeVoteStatusInvalid:
		return pi.ErrorStatusVoteStatusInvalid
	}
	return pi.ErrorStatusInvalid
}

// convertPiErrorStatus attempts to convert the provided politeiad error code
// into a pi ErrorStatusT. If a plugin ID is provided the error code is assumed
// to be a user error code from the specified plugin API.  If no plugin ID is
// provided the error code is assumed to be a user error code from the
// politeiad API.
func convertPiErrorStatus(pluginID string, errCode int) pi.ErrorStatusT {
	switch pluginID {
	case "":
		// politeiad API
		e := pd.ErrorStatusT(errCode)
		return convertPiErrorStatusFromPD(e)
	case piplugin.ID:
		// Pi plugin
		e := piplugin.ErrorCodeT(errCode)
		return convertPiErrorStatusFromPiPlugin(e)
	case comments.ID:
		// Comments plugin
		e := comments.ErrorCodeT(errCode)
		return convertPiErrorStatusFromComments(e)
	case ticketvote.ID:
		// Ticket vote plugin
		e := ticketvote.ErrorCodeT(errCode)
		return convertPiErrorStatusFromTicketVote(e)
	}

	// No corresponding pi error status found
	return pi.ErrorStatusInvalid
}

// Fetch remote identity
func getIdentity(rpcHost, rpcCert, rpcIdentityFile, interactive string) error {
	id, err := util.RemoteIdentity(false, rpcHost, rpcCert)
	if err != nil {
		return err
	}

	// Pretty print identity.
	log.Infof("Identity fetched from politeiad")
	log.Infof("Key        : %x", id.Key)
	log.Infof("Fingerprint: %v", id.Fingerprint())

	if interactive != allowInteractive {
		// Ask user if we like this identity
		log.Infof("Press enter to save to %v or ctrl-c to abort",
			rpcIdentityFile)
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		if err = scanner.Err(); err != nil {
			return err
		}
	} else {
		log.Infof("Saving identity to %v", rpcIdentityFile)
	}

	// Save identity
	err = os.MkdirAll(filepath.Dir(rpcIdentityFile), 0700)
	if err != nil {
		return err
	}
	err = id.SavePublicIdentity(rpcIdentityFile)
	if err != nil {
		return err
	}
	log.Infof("Identity saved to: %v", rpcIdentityFile)

	return nil
}

// respondWithPiError returns an HTTP error status to the client. If it's a pi
// user error, it returns a 4xx HTTP status and the specific user error code.
// If it's an internal server error, it returns 500 and a UNIX timestamp which
// is also outputted to the logs so that it can be correlated later if the user
// files a complaint.
func respondWithPiError(w http.ResponseWriter, r *http.Request, format string, err error) {
	// Check for pi user error
	var ue pi.UserErrorReply
	if errors.As(err, &ue) {
		// Error is a pi user error. Log it and return a 400.
		if len(ue.ErrorContext) == 0 {
			log.Infof("Pi user error: %v %v %v",
				remoteAddr(r), int64(ue.ErrorCode),
				pi.ErrorStatus[ue.ErrorCode])
		} else {
			log.Errorf("Pi user error: %v %v %v: %v",
				remoteAddr(r), int64(ue.ErrorCode),
				pi.ErrorStatus[ue.ErrorCode], ue.ErrorContext)
		}

		util.RespondWithJSON(w, http.StatusBadRequest,
			pi.UserErrorReply{
				ErrorCode:    ue.ErrorCode,
				ErrorContext: ue.ErrorContext,
			})
		return
	}

	// Check for politeiad error
	var pdErr pdError
	if errors.As(err, &pdErr) {
		var (
			pluginID   = pdErr.ErrorReply.Plugin
			errCode    = pdErr.ErrorReply.ErrorCode
			errContext = pdErr.ErrorReply.ErrorContext
		)

		// Check if the politeiad error corresponds to a pi user error
		piErrCode := convertPiErrorStatus(pluginID, errCode)
		if piErrCode == pi.ErrorStatusInvalid {
			// politeiad error does not correspond to a pi user error. Log
			// it and return a 500.
			t := time.Now().Unix()
			if pluginID == "" {
				log.Errorf("%v %v %v %v Internal error %v: error "+
					"code from politeiad: %v", remoteAddr(r), r.Method,
					r.URL, r.Proto, t, errCode)
			} else {
				log.Errorf("%v %v %v %v Internal error %v: error "+
					"code from politeiad plugin %v: %v %v", remoteAddr(r),
					r.Method, r.URL, r.Proto, t, pluginID, errCode, errContext)
			}

			util.RespondWithJSON(w, http.StatusInternalServerError,
				pi.ServerErrorReply{
					ErrorCode: t,
				})
			return
		}

		// politeiad error does correspond to a pi user error. Log it and
		// return a 400.
		if len(errContext) == 0 {
			log.Infof("Pi user error: %v %v %v",
				remoteAddr(r), int64(piErrCode),
				pi.ErrorStatus[piErrCode])
		} else {
			log.Infof("Pi user error: %v %v %v: %v",
				remoteAddr(r), int64(piErrCode),
				pi.ErrorStatus[piErrCode],
				strings.Join(errContext, ", "))
		}

		util.RespondWithJSON(w, http.StatusBadRequest,
			pi.UserErrorReply{
				ErrorCode:    piErrCode,
				ErrorContext: strings.Join(errContext, ", "),
			})
		return

	}

	// Error is a politeiawww server error. Log it and return a 500.
	t := time.Now().Unix()
	e := fmt.Sprintf(format, err)
	log.Errorf("%v %v %v %v Internal error %v: %v",
		remoteAddr(r), r.Method, r.URL, r.Proto, t, e)
	log.Errorf("Stacktrace (NOT A REAL CRASH): %s", debug.Stack())

	util.RespondWithJSON(w, http.StatusInternalServerError,
		pi.ServerErrorReply{
			ErrorCode: t,
		})
}

// userErrorStatus retrieves the human readable error message for an error
// status code. The status code can be from either the pi or cms api.
func userErrorStatus(e www.ErrorStatusT) string {
	s, ok := www.ErrorStatus[e]
	if ok {
		return s
	}
	s, ok = cms.ErrorStatus[e]
	if ok {
		return s
	}
	return ""
}

// RespondWithError returns an HTTP error status to the client. If it's a user
// error, it returns a 4xx HTTP status and the specific user error code. If it's
// an internal server error, it returns 500 and an error code which is also
// outputted to the logs so that it can be correlated later if the user
// files a complaint.
func RespondWithError(w http.ResponseWriter, r *http.Request, userHttpCode int, format string, args ...interface{}) {
	// XXX this function needs to get an error in and a format + args
	// instead of what it is doing now.
	// So inError error, format string, args ...interface{}
	// if err == nil -> internal error using format + args
	// if err != nil -> if defined error -> return defined error + log.Errorf format+args
	// if err != nil -> if !defined error -> return + log.Errorf format+args

	// Check for www user error
	if userErr, ok := args[0].(www.UserError); ok {
		// Error is a www user error. Log it and return a 400.
		if userHttpCode == 0 {
			userHttpCode = http.StatusBadRequest
		}

		if len(userErr.ErrorContext) == 0 {
			log.Infof("WWW user error: %v %v %v",
				remoteAddr(r), int64(userErr.ErrorCode),
				userErrorStatus(userErr.ErrorCode))
		} else {
			log.Infof("WWW user error: %v %v %v: %v",
				remoteAddr(r), int64(userErr.ErrorCode),
				userErrorStatus(userErr.ErrorCode),
				strings.Join(userErr.ErrorContext, ", "))
		}

		util.RespondWithJSON(w, userHttpCode,
			www.UserError{
				ErrorCode:    userErr.ErrorCode,
				ErrorContext: userErr.ErrorContext,
			})
		return
	}

	// Check for politeiad error
	if pdError, ok := args[0].(pdError); ok {
		var (
			pluginID   = pdError.ErrorReply.Plugin
			errCode    = pdError.ErrorReply.ErrorCode
			errContext = pdError.ErrorReply.ErrorContext
		)

		// Check if the politeiad error corresponds to a www user error
		wwwErrCode := convertWWWErrorStatus(pluginID, errCode)
		if wwwErrCode == www.ErrorStatusInvalid {
			// politeiad error does not correspond to a www user error. Log
			// it and return a 500.
			t := time.Now().Unix()
			if pluginID == "" {
				log.Errorf("%v %v %v %v Internal error %v: error "+
					"code from politeiad: %v", remoteAddr(r), r.Method,
					r.URL, r.Proto, t, errCode)
			} else {
				log.Errorf("%v %v %v %v Internal error %v: error "+
					"code from politeiad plugin %v: %v", remoteAddr(r),
					r.Method, r.URL, r.Proto, t, pluginID, errCode)
			}

			util.RespondWithJSON(w, http.StatusInternalServerError,
				www.ErrorReply{
					ErrorCode: t,
				})
			return
		}

		// politeiad error does correspond to a www user error. Log it
		// and return a 400.
		if len(errContext) == 0 {
			log.Infof("WWW user error: %v %v %v",
				remoteAddr(r), int64(wwwErrCode),
				userErrorStatus(wwwErrCode))
		} else {
			log.Infof("WWW user error: %v %v %v: %v",
				remoteAddr(r), int64(wwwErrCode),
				userErrorStatus(wwwErrCode),
				strings.Join(errContext, ", "))
		}

		util.RespondWithJSON(w, http.StatusBadRequest,
			www.UserError{
				ErrorCode:    wwwErrCode,
				ErrorContext: errContext,
			})
		return
	}

	// Error is a politeiawww server error. Log it and return a 500.
	t := time.Now().Unix()
	ec := fmt.Sprintf("%v %v %v %v Internal error %v: ", remoteAddr(r),
		r.Method, r.URL, r.Proto, t)
	log.Errorf(ec+format, args...)
	log.Errorf("Stacktrace (NOT A REAL CRASH): %s", debug.Stack())

	util.RespondWithJSON(w, http.StatusInternalServerError,
		www.ErrorReply{
			ErrorCode: t,
		})
}

// addRoute sets up a handler for a specific method+route. If method is not
// specified it adds a websocket. The routeVersion should be in the format
// "/v1".
func (p *politeiawww) addRoute(method string, routeVersion string, route string, handler http.HandlerFunc, perm permission) {
	fullRoute := routeVersion + route

	switch perm {
	case permissionAdmin:
		handler = p.isLoggedInAsAdmin(handler)
	case permissionLogin:
		handler = p.isLoggedIn(handler)
	}

	if method == "" {
		// Websocket
		log.Tracef("Adding websocket: %v", fullRoute)
		p.router.StrictSlash(true).HandleFunc(fullRoute, handler)
		return
	}

	switch perm {
	case permissionAdmin, permissionLogin:
		// Add route to auth router
		p.auth.StrictSlash(true).HandleFunc(fullRoute, handler).Methods(method)
	default:
		// Add route to public router
		p.router.StrictSlash(true).HandleFunc(fullRoute, handler).Methods(method)
	}
}

func (p *politeiawww) setupPi() error {
	// Setup routes
	p.setPoliteiaWWWRoutes()
	p.setUserWWWRoutes()
	p.setPiRoutes()

	// Verify paywall settings
	switch {
	case p.cfg.PaywallAmount != 0 && p.cfg.PaywallXpub != "":
		// Paywall is enabled
		paywallAmountInDcr := float64(p.cfg.PaywallAmount) / 1e8
		log.Infof("Paywall : %v DCR", paywallAmountInDcr)

	case p.cfg.PaywallAmount == 0 && p.cfg.PaywallXpub == "":
		// Paywall is disabled
		log.Infof("Paywall: DISABLED")

	default:
		// Invalid paywall setting
		return fmt.Errorf("paywall settings invalid, both an amount " +
			"and public key MUST be set")
	}

	// Setup paywall pool
	p.userPaywallPool = make(map[uuid.UUID]paywallPoolMember)
	err := p.initPaywallChecker()
	if err != nil {
		return err
	}

	// Setup event manager
	p.setupEventListenersPi()

	// TODO Verify politeiad plugins

	return nil
}

func (p *politeiawww) setupCMS() error {
	// Setup routes
	p.setCMSWWWRoutes()
	p.setCMSUserWWWRoutes()

	// Setup event manager
	p.setupEventListenersCMS()

	// Setup dcrdata websocket connection
	ws, err := wsdcrdata.New(p.dcrdataHostWS())
	if err != nil {
		// Continue even if a websocket connection was not able to be
		// made. The application specific websocket setup (pi, cms, etc)
		// can decide whether to attempt reconnection or to exit.
		log.Errorf("wsdcrdata New: %v", err)
	}
	p.wsDcrdata = ws

	// Verify politeiad plugins
	pluginFound := false
	for _, plugin := range p.plugins {
		if plugin.ID == "cms" {
			pluginFound = true
			break
		}
	}
	if !pluginFound {
		return fmt.Errorf("politeiad plugin 'cms' not found")
	}

	// Setup cmsdb
	net := filepath.Base(p.cfg.DataDir)
	p.cmsDB, err = cmsdb.New(p.cfg.DBHost, net, p.cfg.DBRootCert,
		p.cfg.DBCert, p.cfg.DBKey)
	if errors.Is(err, database.ErrNoVersionRecord) || errors.Is(err, database.ErrWrongVersion) {
		// The cmsdb version record was either not found or
		// is the wrong version which means that the cmsdb
		// needs to be built/rebuilt.
		p.cfg.BuildCMSDB = true
	} else if err != nil {
		return err
	}
	err = p.cmsDB.Setup()
	if err != nil {
		return fmt.Errorf("cmsdb setup: %v", err)
	}

	// Build the cms database
	if p.cfg.BuildCMSDB {
		index := 0
		// Do pagination since we can't handle the full payload
		count := 50
		dbInvs := make([]database.Invoice, 0, 2048)
		dbDCCs := make([]database.DCC, 0, 2048)
		for {
			log.Infof("requesting record inventory index %v of count %v", index, count)
			// Request full record inventory from backend
			challenge, err := util.Random(pd.ChallengeSize)
			if err != nil {
				return err
			}

			pdCommand := pd.Inventory{
				Challenge:    hex.EncodeToString(challenge),
				IncludeFiles: true,
				AllVersions:  true,
				VettedCount:  uint(count),
				VettedStart:  uint(index),
			}

			ctx := context.Background()
			responseBody, err := p.makeRequest(ctx, http.MethodPost,
				pd.InventoryRoute, pdCommand)
			if err != nil {
				return err
			}

			var pdReply pd.InventoryReply
			err = json.Unmarshal(responseBody, &pdReply)
			if err != nil {
				return fmt.Errorf("Could not unmarshal InventoryReply: %v",
					err)
			}

			// Verify the UpdateVettedMetadata challenge.
			err = util.VerifyChallenge(p.cfg.Identity, challenge, pdReply.Response)
			if err != nil {
				return err
			}

			vetted := pdReply.Vetted
			for _, r := range vetted {
				for _, m := range r.Metadata {
					switch m.ID {
					case mdstream.IDInvoiceGeneral:
						i, err := convertRecordToDatabaseInvoice(r)
						if err != nil {
							log.Errorf("convertRecordToDatabaseInvoice: %v", err)
							break
						}
						u, err := p.db.UserGetByPubKey(i.PublicKey)
						if err != nil {
							log.Errorf("usergetbypubkey: %v %v", err, i.PublicKey)
							break
						}
						i.UserID = u.ID.String()
						i.Username = u.Username
						dbInvs = append(dbInvs, *i)
					case mdstream.IDDCCGeneral:
						d, err := convertRecordToDatabaseDCC(r)
						if err != nil {
							log.Errorf("convertRecordToDatabaseDCC: %v", err)
							break
						}
						dbDCCs = append(dbDCCs, *d)
					}
				}
			}
			if len(vetted) < count {
				break
			}
			index += count
		}

		// Build the cache
		err = p.cmsDB.Build(dbInvs, dbDCCs)
		if err != nil {
			return fmt.Errorf("build cache: %v", err)
		}
	}
	if p.cfg.GithubAPIToken != "" && p.cfg.CodeStatOrganization != "" {
		p.tracker, err = ghtracker.New(p.cfg.GithubAPIToken,
			p.cfg.DBHost, p.cfg.DBRootCert, p.cfg.DBCert, p.cfg.DBKey)
		if err != nil {
			return fmt.Errorf("code tracker failed to load: %v", err)
		}
		go func() {
			err = p.updateCodeStats(p.cfg.CodeStatOrganization,
				p.cfg.CodeStatRepos, p.cfg.CodeStatStart, p.cfg.CodeStatEnd)
			if err != nil {
				log.Errorf("erroring updating code stats %v", err)
			}
		}()
	}

	// Register cms userdb plugin
	plugin := user.Plugin{
		ID:      user.CMSPluginID,
		Version: user.CMSPluginVersion,
	}
	err = p.db.RegisterPlugin(plugin)
	if err != nil {
		return fmt.Errorf("register userdb plugin: %v", err)
	}

	// Setup invoice notifications
	p.cron = cron.New()
	p.checkInvoiceNotifications()

	// Setup dcrdata websocket subscriptions and monitoring. This is
	// done in a go routine so cmswww startup will continue in
	// the event that a dcrdata websocket connection was not able to
	// be made during client initialization and reconnection attempts
	// are required.
	go func() {
		p.setupCMSAddressWatcher()
	}()

	return nil
}

func _main() error {
	// Load configuration and parse command line.  This function also
	// initializes logging and configures it accordingly.
	loadedCfg, _, err := loadConfig()
	if err != nil {
		return fmt.Errorf("Could not load configuration file: %v", err)
	}
	defer func() {
		if logRotator != nil {
			logRotator.Close()
		}
	}()

	log.Infof("Version : %v", version.String())
	log.Infof("Build Version: %v", version.BuildMainVersion())
	log.Infof("Network : %v", activeNetParams.Params.Name)
	log.Infof("Home dir: %v", loadedCfg.HomeDir)

	// Create the data directory in case it does not exist.
	err = os.MkdirAll(loadedCfg.DataDir, 0700)
	if err != nil {
		return err
	}

	// Check if this command is being run to fetch the politeiad
	// identity.
	if loadedCfg.FetchIdentity {
		return getIdentity(loadedCfg.RPCHost, loadedCfg.RPCCert,
			loadedCfg.RPCIdentityFile, loadedCfg.Interactive)
	}

	// Generate the TLS cert and key file if both don't already exist.
	if !fileExists(loadedCfg.HTTPSKey) &&
		!fileExists(loadedCfg.HTTPSCert) {
		log.Infof("Generating HTTPS keypair...")

		err := util.GenCertPair(elliptic.P256(), "politeiadwww",
			loadedCfg.HTTPSCert, loadedCfg.HTTPSKey)
		if err != nil {
			return fmt.Errorf("unable to create https keypair: %v",
				err)
		}

		log.Infof("HTTPS keypair created")
	}

	// Load or create new CSRF key
	log.Infof("Load CSRF key")
	csrfKeyFilename := filepath.Join(loadedCfg.DataDir, "csrf.key")
	fCSRF, err := os.Open(csrfKeyFilename)
	if err != nil {
		if os.IsNotExist(err) {
			key, err := util.Random(csrfKeyLength)
			if err != nil {
				return err
			}

			// Persist key
			fCSRF, err = os.OpenFile(csrfKeyFilename,
				os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
			if err != nil {
				return err
			}
			_, err = fCSRF.Write(key)
			if err != nil {
				return err
			}
			_, err = fCSRF.Seek(0, 0)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}
	csrfKey := make([]byte, csrfKeyLength)
	r, err := fCSRF.Read(csrfKey)
	if err != nil {
		return err
	}
	if r != csrfKeyLength {
		return fmt.Errorf("CSRF key corrupt")
	}
	fCSRF.Close()

	csrfMiddleware := csrf.Protect(
		csrfKey,
		csrf.Path("/"),
		csrf.MaxAge(sessionMaxAge),
	)

	// Setup router
	router := mux.NewRouter()
	router.Use(closeBodyMiddleware)
	router.Use(loggingMiddleware)
	router.Use(recoverMiddleware)

	// Setup a subrouter that is CSRF protected. Authenticated routes
	// are required to use the auth router. The subrouter takes on the
	// configuration of the router that it was spawned from, including
	// all of the middleware that has already been registered.
	auth := router.NewRoute().Subrouter()
	auth.Use(csrfMiddleware)

	// Setup the politeiad client
	pdc, err := pdclient.New(loadedCfg.RPCHost, loadedCfg.RPCUser,
		loadedCfg.RPCPass, loadedCfg.Identity)
	if err != nil {
		return err
	}

	// Setup user database
	log.Infof("User db: %v", loadedCfg.UserDB)

	var userDB user.Database
	switch loadedCfg.UserDB {
	case userDBLevel:
		db, err := localdb.New(loadedCfg.DataDir)
		if err != nil {
			return err
		}
		userDB = db

	case userDBCockroach:
		// If old encryption key is set it means that we need
		// to open a db connection using the old key and then
		// rotate keys.
		var encryptionKey string
		if loadedCfg.OldEncryptionKey != "" {
			encryptionKey = loadedCfg.OldEncryptionKey
		} else {
			encryptionKey = loadedCfg.EncryptionKey
		}

		// Open db connection
		network := filepath.Base(loadedCfg.DataDir)
		db, err := cockroachdb.New(loadedCfg.DBHost, network,
			loadedCfg.DBRootCert, loadedCfg.DBCert, loadedCfg.DBKey,
			encryptionKey)
		if err != nil {
			return fmt.Errorf("new cockroachdb: %v", err)
		}
		userDB = db

		// Rotate keys
		if loadedCfg.OldEncryptionKey != "" {
			err = db.RotateKeys(loadedCfg.EncryptionKey)
			if err != nil {
				return fmt.Errorf("rotate userdb keys: %v", err)
			}
		}

	default:
		return fmt.Errorf("invalid userdb '%v'", loadedCfg.UserDB)
	}

	// Setup sessions store
	var cookieKey []byte
	if cookieKey, err = ioutil.ReadFile(loadedCfg.CookieKeyFile); err != nil {
		log.Infof("Cookie key not found, generating one...")
		cookieKey, err = util.Random(32)
		if err != nil {
			return err
		}
		err = ioutil.WriteFile(loadedCfg.CookieKeyFile, cookieKey, 0400)
		if err != nil {
			return err
		}
		log.Infof("Cookie key generated")
	}
	sessions := newSessionStore(userDB, sessionMaxAge, cookieKey)

	// Setup smtp client
	smtp, err := newSMTP(loadedCfg.MailHost, loadedCfg.MailUser,
		loadedCfg.MailPass, loadedCfg.MailAddress, loadedCfg.SystemCerts,
		loadedCfg.SMTPSkipVerify)
	if err != nil {
		return fmt.Errorf("newSMTP: %v", err)
	}

	// Setup politeiad client
	client, err := util.NewHTTPClient(false, loadedCfg.RPCCert)
	if err != nil {
		return err
	}

	// Setup application context
	p := &politeiawww{
		cfg:          loadedCfg,
		params:       activeNetParams.Params,
		router:       router,
		auth:         auth,
		politeiad:    pdc,
		client:       client,
		smtp:         smtp,
		db:           userDB,
		sessions:     sessions,
		eventManager: newEventManager(),
		ws:           make(map[string]map[string]*wsContext),
		userEmails:   make(map[string]uuid.UUID),
	}

	// Setup politeiad plugins
	p.plugins, err = p.getPluginInventory()
	if err != nil {
		return fmt.Errorf("getPluginInventory: %v", err)
	}

	// Setup email-userID cache
	err = p.initUserEmailsCache()
	if err != nil {
		return err
	}

	// Perform application specific setup
	switch p.cfg.Mode {
	case politeiaWWWMode:
		err = p.setupPi()
		if err != nil {
			return fmt.Errorf("setupPi: %v", err)
		}
	case cmsWWWMode:
		err = p.setupCMS()
		if err != nil {
			return fmt.Errorf("setupCMS: %v", err)
		}
	default:
		return fmt.Errorf("unknown mode: %v", p.cfg.Mode)
	}

	// Bind to a port and pass our router in
	listenC := make(chan error)
	for _, listener := range loadedCfg.Listeners {
		listen := listener
		go func() {
			cfg := &tls.Config{
				MinVersion: tls.VersionTLS12,
				CurvePreferences: []tls.CurveID{
					tls.CurveP256, // BLAME CHROME, NOT ME!
					tls.CurveP521,
					tls.X25519},
				PreferServerCipherSuites: true,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				},
			}
			srv := &http.Server{
				Handler:   p.router,
				Addr:      listen,
				TLSConfig: cfg,
				TLSNextProto: make(map[string]func(*http.Server,
					*tls.Conn, http.Handler)),
			}

			log.Infof("Listen: %v", listen)
			listenC <- srv.ListenAndServeTLS(loadedCfg.HTTPSCert,
				loadedCfg.HTTPSKey)
		}()
	}

	// Tell user we are ready to go.
	log.Infof("Start of day")

	// Setup OS signals
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGINT)
	for {
		select {
		case sig := <-sigs:
			log.Infof("Terminating with %v", sig)
			goto done
		case err := <-listenC:
			log.Errorf("%v", err)
			goto done
		}
	}
done:

	log.Infof("Exiting")

	// Close user db connection
	p.db.Close()

	// Perform application specific shutdown
	switch p.cfg.Mode {
	case politeiaWWWMode:
		// Nothing to do
	case cmsWWWMode:
		p.wsDcrdata.Close()
	}

	return nil
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
