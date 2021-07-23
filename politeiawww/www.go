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
	pdv2 "github.com/decred/politeia/politeiad/api/v2"
	pdclient "github.com/decred/politeia/politeiad/client"
	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	database "github.com/decred/politeia/politeiawww/cmsdatabase"
	cmsdb "github.com/decred/politeia/politeiawww/cmsdatabase/cockroachdb"
	ghtracker "github.com/decred/politeia/politeiawww/codetracker/github"
	"github.com/decred/politeia/politeiawww/config"
	"github.com/decred/politeia/politeiawww/events"
	"github.com/decred/politeia/politeiawww/mail"
	"github.com/decred/politeia/politeiawww/sessions"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/politeiawww/user/cockroachdb"
	"github.com/decred/politeia/politeiawww/user/localdb"
	"github.com/decred/politeia/politeiawww/user/mysql"
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
	}
	return www.ErrorStatusInvalid
}

func convertWWWErrorStatus(pluginID string, errCode int) www.ErrorStatusT {
	switch pluginID {
	case "":
		// politeiad API
		e := pd.ErrorStatusT(errCode)
		return convertWWWErrorStatusFromPD(e)
	}

	// No corresponding www error status found
	return www.ErrorStatusInvalid
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

	// Check if the client dropped the connection
	if err := r.Context().Err(); err == context.Canceled {
		log.Infof("%v %v %v %v client aborted connection",
			util.RemoteAddr(r), r.Method, r.URL, r.Proto)

		// Client dropped the connection. There is no need to
		// respond further.
		return
	}

	// Check for www user error
	if userErr, ok := args[0].(www.UserError); ok {
		// Error is a www user error. Log it and return a 400.
		if userHttpCode == 0 {
			userHttpCode = http.StatusBadRequest
		}

		if len(userErr.ErrorContext) == 0 {
			log.Infof("WWW user error: %v %v %v",
				util.RemoteAddr(r), int64(userErr.ErrorCode),
				userErrorStatus(userErr.ErrorCode))
		} else {
			log.Infof("WWW user error: %v %v %v: %v",
				util.RemoteAddr(r), int64(userErr.ErrorCode),
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
					"code from politeiad: %v", util.RemoteAddr(r), r.Method,
					r.URL, r.Proto, t, errCode)
			} else {
				log.Errorf("%v %v %v %v Internal error %v: error "+
					"code from politeiad plugin %v: %v", util.RemoteAddr(r),
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
				util.RemoteAddr(r), int64(wwwErrCode),
				userErrorStatus(wwwErrCode))
		} else {
			log.Infof("WWW user error: %v %v %v: %v",
				util.RemoteAddr(r), int64(wwwErrCode),
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
	ec := fmt.Sprintf("%v %v %v %v Internal error %v: ", util.RemoteAddr(r),
		r.Method, r.URL, r.Proto, t)
	log.Errorf(ec+format, args...)
	log.Errorf("Stacktrace (NOT A REAL CRASH): %s", debug.Stack())

	util.RespondWithJSON(w, http.StatusInternalServerError,
		www.ErrorReply{
			ErrorCode: t,
		})
}

// addRoute sets up a handler for a specific method+route. If method is not
// specified it adds a websocket.
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

// getPluginInventory returns the politeiad plugin inventory. If a politeiad
// connection cannot be made, the call will be retried every 5 seconds for up
// to 1000 tries.
func (p *politeiawww) getPluginInventory() ([]pdv2.Plugin, error) {
	// Attempt to fetch the plugin inventory from politeiad until
	// either it is successful or the maxRetries has been exceeded.
	var (
		done          bool
		maxRetries    = 1000
		sleepInterval = 5 * time.Second
		plugins       = make([]pdv2.Plugin, 0, 32)
		ctx           = context.Background()
	)
	for retries := 0; !done; retries++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if retries == maxRetries {
			return nil, fmt.Errorf("max retries exceeded")
		}

		pi, err := p.politeiad.PluginInventory(ctx)
		if err != nil {
			log.Infof("cannot get politeiad plugin inventory: %v: retry in %v",
				err, sleepInterval)
			time.Sleep(sleepInterval)
			continue
		}
		plugins = append(plugins, pi...)

		done = true
	}

	return plugins, nil
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
	if p.cfg.GithubAPIToken != "" {
		p.tracker, err = ghtracker.New(p.cfg.GithubAPIToken,
			p.cfg.DBHost, p.cfg.DBRootCert, p.cfg.DBCert, p.cfg.DBKey)
		if err != nil {
			return fmt.Errorf("code tracker failed to load: %v", err)
		}
		go func() {
			err = p.updateCodeStats(p.cfg.CodeStatSkipSync,
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
		csrf.MaxAge(sessions.SessionMaxAge),
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
	pdc, err := pdclient.New(loadedCfg.RPCHost, loadedCfg.RPCCert,
		loadedCfg.RPCUser, loadedCfg.RPCPass, loadedCfg.Identity)
	if err != nil {
		return err
	}

	// Setup user database
	log.Infof("User database: %v", loadedCfg.UserDB)

	var userDB user.Database
	var mailerDB user.MailerDB
	switch loadedCfg.UserDB {
	case userDBLevel:
		db, err := localdb.New(loadedCfg.DataDir)
		if err != nil {
			return err
		}
		userDB = db

	case userDBMySQL, userDBCockroach:
		// If old encryption key is set it means that we need
		// to open a db connection using the old key and then
		// rotate keys.
		var encryptionKey string
		if loadedCfg.OldEncryptionKey != "" {
			encryptionKey = loadedCfg.OldEncryptionKey
		} else {
			encryptionKey = loadedCfg.EncryptionKey
		}

		// Open db connection.
		network := filepath.Base(loadedCfg.DataDir)
		switch loadedCfg.UserDB {
		case userDBMySQL:
			mysql, err := mysql.New(loadedCfg.DBHost,
				loadedCfg.DBPass, network, encryptionKey)
			if err != nil {
				return fmt.Errorf("new mysql db: %v", err)
			}
			userDB = mysql
			mailerDB = mysql
		case userDBCockroach:
			cdb, err := cockroachdb.New(loadedCfg.DBHost, network,
				loadedCfg.DBRootCert, loadedCfg.DBCert, loadedCfg.DBKey,
				encryptionKey)
			if err != nil {
				return fmt.Errorf("new cdb db: %v", err)
			}
			userDB = cdb
			mailerDB = cdb
		}

		// Rotate keys.
		if loadedCfg.OldEncryptionKey != "" {
			err = userDB.RotateKeys(loadedCfg.EncryptionKey)
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

	// Setup politeiad client
	httpClient, err := util.NewHTTPClient(false, loadedCfg.RPCCert)
	if err != nil {
		return err
	}

	// Setup mailer smtp client
	mailer, err := mail.NewClient(loadedCfg.MailHost, loadedCfg.MailUser,
		loadedCfg.MailPass, loadedCfg.MailAddress, loadedCfg.MailCert,
		loadedCfg.MailSkipVerify, loadedCfg.MailRateLimit, mailerDB)
	if err != nil {
		return fmt.Errorf("new mail client: %v", err)
	}

	// Setup application context
	p := &politeiawww{
		cfg:        loadedCfg,
		params:     activeNetParams.Params,
		router:     router,
		auth:       auth,
		politeiad:  pdc,
		http:       httpClient,
		db:         userDB,
		mail:       mailer,
		sessions:   sessions.New(userDB, cookieKey),
		events:     events.NewManager(),
		ws:         make(map[string]map[string]*wsContext),
		userEmails: make(map[string]uuid.UUID),
	}

	// Setup email-userID cache
	err = p.initUserEmailsCache()
	if err != nil {
		return err
	}

	// Perform application specific setup
	switch p.cfg.Mode {
	case config.PoliteiaWWWMode:
		err = p.setupPi()
		if err != nil {
			return fmt.Errorf("setupPi: %v", err)
		}
	case config.CMSWWWMode:
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
	case config.PoliteiaWWWMode:
		// Nothing to do
	case config.CMSWWWMode:
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
