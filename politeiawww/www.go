// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"crypto/elliptic"
	"crypto/tls"
	_ "encoding/gob"
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

	"github.com/thi4go/politeia/mdstream"
	"github.com/thi4go/politeia/politeiad/cache"
	cachedb "github.com/thi4go/politeia/politeiad/cache/cockroachdb"
	cms "github.com/thi4go/politeia/politeiawww/api/cms/v1"
	www "github.com/thi4go/politeia/politeiawww/api/www/v1"
	database "github.com/thi4go/politeia/politeiawww/cmsdatabase"
	cmsdb "github.com/thi4go/politeia/politeiawww/cmsdatabase/cockroachdb"
	"github.com/thi4go/politeia/politeiawww/user"
	userdb "github.com/thi4go/politeia/politeiawww/user/cockroachdb"
	"github.com/thi4go/politeia/politeiawww/user/localdb"
	"github.com/thi4go/politeia/util"
	"github.com/thi4go/politeia/util/version"
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
	if userErr, ok := args[0].(www.UserError); ok {
		if userHttpCode == 0 {
			userHttpCode = http.StatusBadRequest
		}

		if len(userErr.ErrorContext) == 0 {
			log.Errorf("RespondWithError: %v %v %v",
				remoteAddr(r),
				int64(userErr.ErrorCode),
				userErrorStatus(userErr.ErrorCode))
		} else {
			log.Errorf("RespondWithError: %v %v %v: %v",
				remoteAddr(r),
				int64(userErr.ErrorCode),
				userErrorStatus(userErr.ErrorCode),
				strings.Join(userErr.ErrorContext, ", "))
		}

		util.RespondWithJSON(w, userHttpCode,
			www.ErrorReply{
				ErrorCode:    int64(userErr.ErrorCode),
				ErrorContext: userErr.ErrorContext,
			})
		return
	}

	if pdError, ok := args[0].(www.PDError); ok {
		pdErrorCode := convertErrorStatusFromPD(pdError.ErrorReply.ErrorCode)
		if pdErrorCode == www.ErrorStatusInvalid {
			errorCode := time.Now().Unix()
			log.Errorf("%v %v %v %v Internal error %v: error "+
				"code from politeiad: %v", remoteAddr(r),
				r.Method, r.URL, r.Proto, errorCode,
				pdError.ErrorReply.ErrorCode)
			util.RespondWithJSON(w, http.StatusInternalServerError,
				www.ErrorReply{
					ErrorCode: errorCode,
				})
			return
		}

		util.RespondWithJSON(w, pdError.HTTPCode,
			www.ErrorReply{
				ErrorCode:    int64(pdErrorCode),
				ErrorContext: pdError.ErrorReply.ErrorContext,
			})
		return
	}

	errorCode := time.Now().Unix()
	ec := fmt.Sprintf("%v %v %v %v Internal error %v: ", remoteAddr(r),
		r.Method, r.URL, r.Proto, errorCode)
	log.Errorf(ec+format, args...)
	log.Errorf("Stacktrace (NOT A REAL CRASH): %s", debug.Stack())

	util.RespondWithJSON(w, http.StatusInternalServerError,
		www.ErrorReply{
			ErrorCode: errorCode,
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

// makeRequest makes an http request to the method and route provided,
// serializing the provided object as the request body.
//
// XXX doesn't belong in this file but stuff it here for now.
func (p *politeiawww) makeRequest(method string, route string, v interface{}) ([]byte, error) {
	var (
		requestBody []byte
		err         error
	)
	if v != nil {
		requestBody, err = json.Marshal(v)
		if err != nil {
			return nil, err
		}
	}

	fullRoute := p.cfg.RPCHost + route

	if p.client == nil {
		p.client, err = util.NewClient(false, p.cfg.RPCCert)
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequest(method, fullRoute,
		bytes.NewReader(requestBody))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(p.cfg.RPCUser, p.cfg.RPCPass)
	r, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		var pdErrorReply www.PDErrorReply
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&pdErrorReply); err != nil {
			return nil, err
		}

		return nil, www.PDError{
			HTTPCode:   r.StatusCode,
			ErrorReply: pdErrorReply,
		}
	}

	responseBody := util.ConvertBodyToByteArray(r.Body, false)
	return responseBody, nil
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

	// Issue a warning if pi was builded locally and does not
	// have the main module info available.
	if version.BuildMainVersion() == "(devel)" {
		log.Warnf("Warning: no build information available")
	}

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
		cfg:       loadedCfg,
		ws:        make(map[string]map[string]*wsContext),
		templates: make(map[string]*template.Template),

		// XXX reevaluate where this goes
		userEmails:      make(map[string]uuid.UUID),
		userPaywallPool: make(map[uuid.UUID]paywallPoolMember),
		commentVotes:    make(map[string]counters),
		voteSummaries:   make(map[string]www.VoteSummary),
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
		// localdb.UseLogger(localdbLog)
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

		// Setup logging
		userdb.UseLogger(cockroachdbLog)

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

	// Setup cache connection
	cachedb.UseLogger(cockroachdbLog)
	net := filepath.Base(p.cfg.DataDir)
	p.cache, err = cachedb.New(cachedb.UserPoliteiawww, p.cfg.DBHost,
		net, p.cfg.DBRootCert, p.cfg.DBCert, p.cfg.DBKey)
	if err != nil {
		switch err {
		case cache.ErrNoVersionRecord:
			err = fmt.Errorf("cache version record not found; " +
				"start politeiad to setup the cache")
		case cache.ErrWrongVersion:
			err = fmt.Errorf("wrong cache version found; " +
				"restart politeiad to rebuild the cache")
		}
		return fmt.Errorf("cachedb new: %v", err)
	}

	// Register plugins with cache
	for _, v := range p.plugins {
		cp := convertPluginToCache(v)
		err = p.cache.RegisterPlugin(cp)
		if err != nil {
			switch err {
			case cache.ErrNoVersionRecord:
				err = fmt.Errorf("version record not found;" +
					"start politeiad to setup the cache")
			case cache.ErrWrongVersion:
				err = fmt.Errorf("wrong version found; " +
					"restart politeiad to rebuild the cache")
			}
			return fmt.Errorf("cache register plugin '%v': %v",
				v.ID, err)
		}

		log.Infof("Registered cache plugin: %v", v.ID)
	}

	// Setup email-userID map
	err = p.initUserEmailsCache()
	if err != nil {
		return err
	}

	// Setup comment scores map
	err = p.initCommentScores()
	if err != nil {
		return fmt.Errorf("initCommentScore: %v", err)
	}

	// Set up the code that checks for paywall payments.
	if p.cfg.Mode == "piwww" {
		err = p.initPaywallChecker()
		if err != nil {
			return err
		}
		p.initEventManager()
	} else if p.cfg.Mode == "cmswww" {
		p.initCMSEventManager()
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

	// Setup dcrdata websocket connection
	ws, err := newWSDcrdata(p.dcrdataHostWS())
	if err != nil {
		return fmt.Errorf("new wsDcrdata: %v", err)
	}
	p.wsDcrdata = ws

	switch p.cfg.Mode {
	case politeiaWWWMode:
		p.setPoliteiaWWWRoutes()
		// XXX setup user routes
		p.setUserWWWRoutes()
		err = p.setupPiDcrdataWSSubs()
		if err != nil {
			// Politeiawww can run without a dcrdata subscription, but this
			// should be logged.
			log.Errorf("Unable to setup pi dcrdata subs: %v", err)
		}
	case cmsWWWMode:
		p.setCMSWWWRoutes()
		// XXX setup user routes
		p.setCMSUserWWWRoutes()

		// Setup cmsdb
		cmsdb.UseLogger(cockroachdbLog)
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
			// Fetch all versions of all records from the inventory and
			// use them to build the cache.
			vetted, err := p.cache.Inventory()
			if err != nil {
				return fmt.Errorf("backend inventory: %v", err)
			}

			dbInvs := make([]database.Invoice, 0, len(vetted))
			dbDCCs := make([]database.DCC, 0, len(vetted))
			for _, r := range vetted {
				for _, m := range r.Metadata {
					switch m.ID {
					case mdstream.IDInvoiceGeneral:
						i, err := convertCacheToDatabaseInvoice(r)
						if err != nil {
							log.Errorf("convertCacheToDatabaseInvoice: %v", err)
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
						d, err := convertCacheToDatabaseDCC(r)
						if err != nil {
							log.Errorf("convertCacheToDatabaseDCC: %v", err)
							break
						}
						dbDCCs = append(dbDCCs, *d)
					}
				}
			}

			// Build the cache
			err = p.cmsDB.Build(dbInvs, dbDCCs)
			if err != nil {
				return fmt.Errorf("build cache: %v", err)
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

		p.setupCMSAddressWatcher()
		err = p.restartCMSAddressesWatching()
		if err != nil {
			log.Errorf("error restarting address watcher %v", err)
		}

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
		p.wsDcrdata.close()
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
