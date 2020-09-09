// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"crypto/elliptic"
	"crypto/tls"
	_ "encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"text/template"
	"time"

	"github.com/decred/politeia/mdstream"
	"github.com/decred/politeia/plugins/comments"
	piplugin "github.com/decred/politeia/plugins/pi"
	"github.com/decred/politeia/plugins/ticketvote"
	pd "github.com/decred/politeia/politeiad/api/v1"
	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	pi "github.com/decred/politeia/politeiawww/api/pi/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	database "github.com/decred/politeia/politeiawww/cmsdatabase"
	cmsdb "github.com/decred/politeia/politeiawww/cmsdatabase/cockroachdb"
	"github.com/decred/politeia/politeiawww/user"
	userdb "github.com/decred/politeia/politeiawww/user/cockroachdb"
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
	case pd.ErrorStatusInvalidRequestPayload:
		// Intentionally omitted because this indicates a politeiawww
		// server error so a ErrorStatusInvalid should be returned.
	case pd.ErrorStatusInvalidChallenge:
		// Intentionally omitted because this indicates a politeiawww
		// server error so a ErrorStatusInvalid should be returned.
	}
	return www.ErrorStatusInvalid
}

func convertWWWErrorStatusFromPiPlugin(e piplugin.ErrorStatusT) www.ErrorStatusT {
	switch e {
	case piplugin.ErrorStatusPropLinkToInvalid:
		return www.ErrorStatusInvalidLinkTo
	case piplugin.ErrorStatusPropStatusInvalid:
		return www.ErrorStatusWrongStatus
	case piplugin.ErrorStatusVoteStatusInvalid:
		return www.ErrorStatusWrongVoteStatus
	}
	return www.ErrorStatusInvalid
}

func convertWWWErrorStatusFromComments(e comments.ErrorStatusT) www.ErrorStatusT {
	switch e {
	case comments.ErrorStatusTokenInvalid:
		return www.ErrorStatusInvalidCensorshipToken
	case comments.ErrorStatusPublicKeyInvalid:
		return www.ErrorStatusInvalidPublicKey
	case comments.ErrorStatusSignatureInvalid:
		return www.ErrorStatusInvalidSignature
	case comments.ErrorStatusRecordNotFound:
		return www.ErrorStatusProposalNotFound
	case comments.ErrorStatusCommentNotFound:
		return www.ErrorStatusCommentNotFound
	case comments.ErrorStatusParentIDInvalid:
		return www.ErrorStatusCommentNotFound
	case comments.ErrorStatusNoCommentChanges:
		// Intentionally omitted. The www API does not allow for comment
		// changes.
	case comments.ErrorStatusVoteInvalid:
		return www.ErrorStatusInvalidLikeCommentAction
	case comments.ErrorStatusMaxVoteChanges:
		return www.ErrorStatusInvalidLikeCommentAction
	}
	return www.ErrorStatusInvalid
}

func convertWWWErrorStatusFromTicketVote(e ticketvote.ErrorStatusT) www.ErrorStatusT {
	switch e {
	case ticketvote.ErrorStatusTokenInvalid:
		return www.ErrorStatusInvalidCensorshipToken
	case ticketvote.ErrorStatusPublicKeyInvalid:
		return www.ErrorStatusInvalidPublicKey
	case ticketvote.ErrorStatusSignatureInvalid:
		return www.ErrorStatusInvalidSignature
	case ticketvote.ErrorStatusRecordNotFound:
		return www.ErrorStatusProposalNotFound
	case ticketvote.ErrorStatusRecordStatusInvalid:
		return www.ErrorStatusWrongStatus
	case ticketvote.ErrorStatusVoteDetailsInvalid:
		return www.ErrorStatusInvalidPropVoteParams
	case ticketvote.ErrorStatusVoteStatusInvalid:
		return www.ErrorStatusInvalidPropVoteStatus
	case ticketvote.ErrorStatusBallotInvalid:
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
		e := piplugin.ErrorStatusT(errCode)
		return convertWWWErrorStatusFromPiPlugin(e)
	case comments.ID:
		// Comments plugin
		e := comments.ErrorStatusT(errCode)
		return convertWWWErrorStatusFromComments(e)
	case ticketvote.ID:
		// Ticket vote plugin
		e := ticketvote.ErrorStatusT(errCode)
		return convertWWWErrorStatusFromTicketVote(e)
	}

	// No corresponding www error status found
	return www.ErrorStatusInvalid
}

func convertPiErrorStatusFromPD(e pd.ErrorStatusT) pi.ErrorStatusT {
	switch e {
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
	case pd.ErrorStatusInvalidRequestPayload:
		// Intentionally omitted because this indicates a politeiawww
		// server error so a ErrorStatusInvalid should be returned.
	case pd.ErrorStatusInvalidChallenge:
		// Intentionally omitted because this indicates a politeiawww
		// server error so a ErrorStatusInvalid should be returned.
	}
	return pi.ErrorStatusInvalid
}

func convertPiErrorStatusFromPiPlugin(e piplugin.ErrorStatusT) pi.ErrorStatusT {
	switch e {
	case piplugin.ErrorStatusPropLinkToInvalid:
		return pi.ErrorStatusPropLinkToInvalid
	case piplugin.ErrorStatusPropStatusInvalid:
		return pi.ErrorStatusPropStatusInvalid
	case piplugin.ErrorStatusVoteStatusInvalid:
		return pi.ErrorStatusVoteStatusInvalid
	}
	return pi.ErrorStatusInvalid
}

func convertPiErrorStatusFromComments(e comments.ErrorStatusT) pi.ErrorStatusT {
	switch e {
	case comments.ErrorStatusTokenInvalid:
		return pi.ErrorStatusPropTokenInvalid
	case comments.ErrorStatusPublicKeyInvalid:
		return pi.ErrorStatusPublicKeyInvalid
	case comments.ErrorStatusSignatureInvalid:
		return pi.ErrorStatusSignatureInvalid
	case comments.ErrorStatusRecordNotFound:
		return pi.ErrorStatusPropNotFound
	case comments.ErrorStatusCommentNotFound:
		return pi.ErrorStatusCommentNotFound
	case comments.ErrorStatusParentIDInvalid:
		return pi.ErrorStatusCommentParentIDInvalid
	case comments.ErrorStatusNoCommentChanges:
		return pi.ErrorStatusCommentTextInvalid
	case comments.ErrorStatusVoteInvalid:
		return pi.ErrorStatusCommentVoteInvalid
	case comments.ErrorStatusMaxVoteChanges:
		return pi.ErrorStatusCommentMaxVoteChanges
	}
	return pi.ErrorStatusInvalid
}

func convertPiErrorStatusFromTicketVote(e ticketvote.ErrorStatusT) pi.ErrorStatusT {
	switch e {
	case ticketvote.ErrorStatusTokenInvalid:
		return pi.ErrorStatusPropTokenInvalid
	case ticketvote.ErrorStatusPublicKeyInvalid:
		return pi.ErrorStatusPublicKeyInvalid
	case ticketvote.ErrorStatusSignatureInvalid:
		return pi.ErrorStatusSignatureInvalid
	case ticketvote.ErrorStatusRecordNotFound:
		return pi.ErrorStatusPropNotFound
	case ticketvote.ErrorStatusRecordStatusInvalid:
		return pi.ErrorStatusPropStatusInvalid
	case ticketvote.ErrorStatusVoteDetailsInvalid:
		return pi.ErrorStatusVoteDetailsInvalid
	case ticketvote.ErrorStatusVoteStatusInvalid:
		return pi.ErrorStatusVoteStatusInvalid
	case ticketvote.ErrorStatusBallotInvalid:
		return pi.ErrorStatusBallotInvalid
	}
	return pi.ErrorStatusInvalid
}

// convertPiErrorStatus attempts to convert the provided politeiad plugin ID
// and error code into a pi ErrorStatusT. If a plugin ID is provided the error
// code is assumed to be a user error code from the specified plugin API.  If
// no plugin ID is provided the error code is assumed to be a user error code
// from the politeiad API.
func convertPiErrorStatus(pluginID string, errCode int) pi.ErrorStatusT {
	switch pluginID {
	case "":
		// politeiad API
		e := pd.ErrorStatusT(errCode)
		return convertPiErrorStatusFromPD(e)
	case piplugin.ID:
		// Pi plugin
		e := piplugin.ErrorStatusT(errCode)
		return convertPiErrorStatusFromPiPlugin(e)
	case comments.ID:
		// Comments plugin
		e := comments.ErrorStatusT(errCode)
		return convertPiErrorStatusFromComments(e)
	case ticketvote.ID:
		// Ticket vote plugin
		e := ticketvote.ErrorStatusT(errCode)
		return convertPiErrorStatusFromTicketVote(e)
	}

	// No corresponding pi error status found
	return pi.ErrorStatusInvalid
}

// Fetch remote identity
func (p *politeiawww) getIdentity() error {
	id, err := util.RemoteIdentity(false, p.cfg.RPCHost, p.cfg.RPCCert)
	if err != nil {
		return err
	}

	// Pretty print identity.
	log.Infof("Identity fetched from politeiad")
	log.Infof("Key        : %x", id.Key)
	log.Infof("Fingerprint: %v", id.Fingerprint())

	if p.cfg.Interactive != allowInteractive {
		// Ask user if we like this identity
		log.Infof("Press enter to save to %v or ctrl-c to abort",
			p.cfg.RPCIdentityFile)
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		if err = scanner.Err(); err != nil {
			return err
		}
	} else {
		log.Infof("Saving identity to %v", p.cfg.RPCIdentityFile)
	}

	// Save identity
	err = os.MkdirAll(filepath.Dir(p.cfg.RPCIdentityFile), 0700)
	if err != nil {
		return err
	}
	err = id.SavePublicIdentity(p.cfg.RPCIdentityFile)
	if err != nil {
		return err
	}
	log.Infof("Identity saved to: %v", p.cfg.RPCIdentityFile)

	return nil
}

// respondWithPiError returns an HTTP error status to the client. If it's a pi
// user error, it returns a 4xx HTTP status and the specific user error code.
// If it's an internal server error, it returns 500 and a UNIX timestamp which
// is also outputted to the logs so that it can be correlated later if the user
// files a complaint.
func respondWithPiError(w http.ResponseWriter, r *http.Request, format string, err error) {
	// Check for pi user error
	if ue, ok := err.(pi.UserErrorReply); ok {
		// Error is a pi user error. Log it and return a 400.
		if len(ue.ErrorContext) == 0 {
			log.Infof("Pi user error: %v %v %v",
				remoteAddr(r), int64(ue.ErrorCode),
				pi.ErrorStatus[ue.ErrorCode])
		} else {
			log.Errorf("Pi user error: %v %v %v: %v",
				remoteAddr(r), int64(ue.ErrorCode),
				pi.ErrorStatus[ue.ErrorCode],
				strings.Join(ue.ErrorContext, ", "))
		}

		util.RespondWithJSON(w, http.StatusBadRequest,
			pi.UserErrorReply{
				ErrorCode:    ue.ErrorCode,
				ErrorContext: ue.ErrorContext,
			})
		return
	}

	// Check for politeiad error
	if pdErr, ok := err.(pdError); ok {
		var (
			pluginID   = pdErr.ErrorReply.PluginID
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
					"code from politeiad plugin %v: %v", remoteAddr(r),
					r.Method, r.URL, r.Proto, t, pluginID, errCode)
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
				ErrorContext: errContext,
			})
		return

	}

	// Error is a politeiawww server error. Log it and return a 500.
	t := time.Now().Unix()
	log.Errorf("%v %v %v %v Internal error %v: %v",
		remoteAddr(r), r.Method, r.URL, r.Proto, t, format)
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
			pluginID   = pdError.ErrorReply.PluginID
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
		handler = logging(p.isLoggedInAsAdmin(handler))
	case permissionLogin:
		handler = logging(p.isLoggedIn(handler))
	default:
		handler = logging(handler)
	}

	// All handlers need to close the body
	handler = closeBody(handler)

	if method == "" {
		// Websocket
		log.Tracef("Adding websocket: %v", fullRoute)
		p.router.StrictSlash(true).HandleFunc(fullRoute, handler)
	} else {
		p.router.StrictSlash(true).HandleFunc(fullRoute, handler).Methods(method)
	}
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

	if loadedCfg.PaywallAmount != 0 && loadedCfg.PaywallXpub != "" {
		paywallAmountInDcr := float64(loadedCfg.PaywallAmount) / 1e8
		log.Infof("Paywall : %v DCR", paywallAmountInDcr)
	} else if loadedCfg.PaywallAmount == 0 && loadedCfg.PaywallXpub == "" {
		log.Infof("Paywall : DISABLED")
	} else {
		return fmt.Errorf("Paywall settings invalid, both an amount " +
			"and public key MUST be set")
	}

	if loadedCfg.MailHost == "" {
		log.Infof("Email   : DISABLED")
	}

	// Create the data directory in case it does not exist.
	err = os.MkdirAll(loadedCfg.DataDir, 0700)
	if err != nil {
		return err
	}

	// Generate the TLS cert and key file if both don't already
	// exist.
	if !fileExists(loadedCfg.HTTPSKey) &&
		!fileExists(loadedCfg.HTTPSCert) {
		log.Infof("Generating HTTPS keypair...")

		err := util.GenCertPair(elliptic.P256(), "politeiadwww",
			loadedCfg.HTTPSCert, loadedCfg.HTTPSKey)
		if err != nil {
			return fmt.Errorf("unable to create https keypair: %v",
				err)
		}

		log.Infof("HTTPS keypair created...")
	}

	// Setup application context.
	p := &politeiawww{
		cfg:          loadedCfg,
		ws:           make(map[string]map[string]*wsContext),
		templates:    make(map[string]*template.Template),
		eventManager: newEventManager(),

		// XXX reevaluate where this goes
		userEmails:      make(map[string]uuid.UUID),
		userPaywallPool: make(map[uuid.UUID]paywallPoolMember),
		commentVotes:    make(map[string]counters),
		params:          activeNetParams.Params,
	}

	// Check if this command is being run to fetch the identity.
	if p.cfg.FetchIdentity {
		return p.getIdentity()
	}

	// Setup email
	smtp, err := newSMTP(p.cfg.MailHost, p.cfg.MailUser,
		p.cfg.MailPass, p.cfg.MailAddress, p.cfg.SystemCerts,
		p.cfg.SMTPSkipVerify)
	if err != nil {
		return fmt.Errorf("unable to initialize SMTP client: %v",
			err)
	}
	p.smtp = smtp

	// Setup user database
	switch p.cfg.UserDB {
	case userDBLevel:
		db, err := localdb.New(p.cfg.DataDir)
		if err != nil {
			return err
		}
		p.db = db
	case userDBCockroach:
		// If old encryption key is set it means that we need
		// to open a db connection using the old key and then
		// rotate keys.
		var encryptionKey string
		if p.cfg.OldEncryptionKey != "" {
			encryptionKey = p.cfg.OldEncryptionKey
		} else {
			encryptionKey = p.cfg.EncryptionKey
		}

		// Open db connection
		network := filepath.Base(p.cfg.DataDir)
		db, err := userdb.New(p.cfg.DBHost, network, p.cfg.DBRootCert,
			p.cfg.DBCert, p.cfg.DBKey, encryptionKey)
		if err != nil {
			return fmt.Errorf("new cockroachdb: %v", err)
		}
		p.db = db

		// Rotate keys
		if p.cfg.OldEncryptionKey != "" {
			err = db.RotateKeys(p.cfg.EncryptionKey)
			if err != nil {
				return fmt.Errorf("rotate userdb keys: %v", err)
			}
		}
	default:
		return fmt.Errorf("no user db option found")
	}

	// Get plugins from politeiad
	p.plugins, err = p.getPluginInventory()
	if err != nil {
		return fmt.Errorf("getPluginInventory: %v", err)
	}

	// Setup email-userID map
	err = p.initUserEmailsCache()
	if err != nil {
		return err
	}

	// Load or create new CSRF key
	log.Infof("Load CSRF key")
	csrfKeyFilename := filepath.Join(p.cfg.DataDir, "csrf.key")
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

	csrfHandle := csrf.Protect(
		csrfKey,
		csrf.Path("/"),
		csrf.MaxAge(sessionMaxAge),
	)

	p.router = mux.NewRouter()
	p.router.Use(recoverMiddleware)

	switch p.cfg.Mode {
	case politeiaWWWMode:
		// Setup routes
		p.setPoliteiaWWWRoutes()
		p.setUserWWWRoutes()

		err = p.initPaywallChecker()
		if err != nil {
			return err
		}

		p.initEventManagerPi()
		p.setupEventListenersPi()

	case cmsWWWMode:
		// Setup event manager
		p.initCMSEventManager()

		// Setup dcrdata websocket connection
		ws, err := wsdcrdata.New(p.dcrdataHostWS())
		if err != nil {
			// Continue even if a websocket connection was not able to be
			// made. The application specific websocket setup (pi, cms, etc)
			// can decide whether to attempt reconnection or to exit.
			log.Errorf("wsdcrdata New: %v", err)
		}
		p.wsDcrdata = ws

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

		p.setCMSWWWRoutes()
		// XXX setup user routes
		p.setCMSUserWWWRoutes()

		// Setup cmsdb
		net := filepath.Base(p.cfg.DataDir)
		p.cmsDB, err = cmsdb.New(p.cfg.DBHost, net, p.cfg.DBRootCert,
			p.cfg.DBCert, p.cfg.DBKey)
		if err == database.ErrNoVersionRecord || err == database.ErrWrongVersion {
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
			// Request full record inventory from backend
			challenge, err := util.Random(pd.ChallengeSize)
			if err != nil {
				return err
			}

			pdCommand := pd.Inventory{
				Challenge:    hex.EncodeToString(challenge),
				IncludeFiles: true,
				AllVersions:  true,
			}

			responseBody, err := p.makeRequest(http.MethodPost,
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
			dbInvs := make([]database.Invoice, 0, len(vetted))
			dbDCCs := make([]database.DCC, 0, len(vetted))
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

			// Build the cmsdb
			err = p.cmsDB.Build(dbInvs, dbDCCs)
			if err != nil {
				return fmt.Errorf("build cmsdb: %v", err)
			}
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

	default:
		return fmt.Errorf("unknown mode: %v", p.cfg.Mode)
	}
	// Persist session cookies.
	var cookieKey []byte
	if cookieKey, err = ioutil.ReadFile(p.cfg.CookieKeyFile); err != nil {
		log.Infof("Cookie key not found, generating one...")
		cookieKey, err = util.Random(32)
		if err != nil {
			return err
		}
		err = ioutil.WriteFile(p.cfg.CookieKeyFile, cookieKey, 0400)
		if err != nil {
			return err
		}
		log.Infof("Cookie key generated.")
	}
	sessionsDir := filepath.Join(p.cfg.DataDir, "sessions")
	err = os.MkdirAll(sessionsDir, 0700)
	if err != nil {
		return err
	}
	p.sessions = NewSessionStore(p.db, sessionMaxAge, cookieKey)

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
				Handler:   csrfHandle(p.router),
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

	// Shutdown all dcrdata websockets
	if p.wsDcrdata != nil {
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
