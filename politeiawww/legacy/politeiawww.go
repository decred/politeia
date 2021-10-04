// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package legacy

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/politeia/mdstream"
	pd "github.com/decred/politeia/politeiad/api/v1"
	pdv2 "github.com/decred/politeia/politeiad/api/v2"
	pdclient "github.com/decred/politeia/politeiad/client"
	cmplugin "github.com/decred/politeia/politeiad/plugins/comments"
	piplugin "github.com/decred/politeia/politeiad/plugins/pi"
	tkplugin "github.com/decred/politeia/politeiad/plugins/ticketvote"
	umplugin "github.com/decred/politeia/politeiad/plugins/usermd"
	"github.com/decred/politeia/politeiawww/config"
	"github.com/decred/politeia/politeiawww/events"
	"github.com/decred/politeia/politeiawww/legacy/cmsdatabase"
	database "github.com/decred/politeia/politeiawww/legacy/cmsdatabase"
	cmsdb "github.com/decred/politeia/politeiawww/legacy/cmsdatabase/cockroachdb"
	"github.com/decred/politeia/politeiawww/legacy/codetracker"
	ghtracker "github.com/decred/politeia/politeiawww/legacy/codetracker/github"
	"github.com/decred/politeia/politeiawww/legacy/comments"
	"github.com/decred/politeia/politeiawww/legacy/pi"
	"github.com/decred/politeia/politeiawww/legacy/ticketvote"
	"github.com/decred/politeia/politeiawww/legacy/user"
	"github.com/decred/politeia/politeiawww/legacy/user/cockroachdb"
	"github.com/decred/politeia/politeiawww/legacy/user/localdb"
	"github.com/decred/politeia/politeiawww/legacy/user/mysql"
	"github.com/decred/politeia/politeiawww/mail"
	"github.com/decred/politeia/politeiawww/records"
	"github.com/decred/politeia/politeiawww/sessions"
	"github.com/decred/politeia/util"
	"github.com/decred/politeia/wsdcrdata"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/robfig/cron"
)

// Politeiawww represents the legacy politeiawww server.
type Politeiawww struct {
	sync.RWMutex
	cfg       *config.Config
	params    *chaincfg.Params
	router    *mux.Router // Public router
	auth      *mux.Router // CSRF protected router
	db        user.Database
	sessions  *sessions.Sessions
	mail      mail.Mailer
	events    *events.Manager
	http      *http.Client // Deprecated politeiad client
	politeiad *pdclient.Client

	// userEmails contains a mapping of all user emails to user ID.
	// This is required for now because the email is stored as part of
	// the encrypted user blob in the user database, but we also allow
	// the user to sign in using their email address, requiring a user
	// lookup by email. This is a temporary measure and should be
	// removed once all user by email lookups have been taken out.
	userEmails map[string]uuid.UUID // [email]userID

	// The following fields are only used during piwww mode.
	userPaywallPool map[uuid.UUID]paywallPoolMember // [userid][paywallPoolMember]

	// The following fields are use only during cmswww mode.
	cmsDB     cmsdatabase.Database
	cron      *cron.Cron
	wsDcrdata *wsdcrdata.Client
	tracker   codetracker.CodeTracker

	// The following fields are only used during testing.
	test bool
}

// NewPoliteiawww returns a new legacy Politeiawww.
func NewPoliteiawww(cfg *config.Config, router, auth *mux.Router, params *chaincfg.Params, pdclient *pdclient.Client) (*Politeiawww, error) {
	// Setup http client for politeiad calls
	httpClient, err := util.NewHTTPClient(false, cfg.RPCCert)
	if err != nil {
		return nil, err
	}

	// Setup user database
	log.Infof("User database: %v", cfg.UserDB)

	var userDB user.Database
	var mailerDB user.MailerDB
	switch cfg.UserDB {
	case config.LevelDB:
		db, err := localdb.New(cfg.DataDir)
		if err != nil {
			return nil, err
		}
		userDB = db

	case config.MySQL, config.CockroachDB:
		// If old encryption key is set it means that we need
		// to open a db connection using the old key and then
		// rotate keys.
		var encryptionKey string
		if cfg.OldEncryptionKey != "" {
			encryptionKey = cfg.OldEncryptionKey
		} else {
			encryptionKey = cfg.EncryptionKey
		}

		// Open db connection.
		network := filepath.Base(cfg.DataDir)
		switch cfg.UserDB {
		case config.MySQL:
			mysql, err := mysql.New(cfg.DBHost,
				cfg.DBPass, network, encryptionKey)
			if err != nil {
				return nil, fmt.Errorf("new mysql db: %v", err)
			}
			userDB = mysql
			mailerDB = mysql
		case config.CockroachDB:
			cdb, err := cockroachdb.New(cfg.DBHost, network,
				cfg.DBRootCert, cfg.DBCert, cfg.DBKey,
				encryptionKey)
			if err != nil {
				return nil, fmt.Errorf("new cdb db: %v", err)
			}
			userDB = cdb
			mailerDB = cdb
		}

		// Rotate keys.
		if cfg.OldEncryptionKey != "" {
			err = userDB.RotateKeys(cfg.EncryptionKey)
			if err != nil {
				return nil, fmt.Errorf("rotate userdb keys: %v", err)
			}
		}

	default:
		return nil, fmt.Errorf("invalid userdb '%v'", cfg.UserDB)
	}

	// Setup sessions store
	var cookieKey []byte
	if cookieKey, err = ioutil.ReadFile(cfg.CookieKeyFile); err != nil {
		log.Infof("Cookie key not found, generating one...")
		cookieKey, err = util.Random(32)
		if err != nil {
			return nil, err
		}
		err = ioutil.WriteFile(cfg.CookieKeyFile, cookieKey, 0400)
		if err != nil {
			return nil, err
		}
		log.Infof("Cookie key generated")
	}

	// Setup mailer smtp client
	mailer, err := mail.NewClient(cfg.MailHost, cfg.MailUser,
		cfg.MailPass, cfg.MailAddress, cfg.MailCert,
		cfg.MailSkipVerify, cfg.MailRateLimit, mailerDB)
	if err != nil {
		return nil, fmt.Errorf("new mail client: %v", err)
	}

	// Setup legacy politeiawww context
	p := &Politeiawww{
		cfg:             cfg,
		params:          params,
		router:          router,
		auth:            auth,
		politeiad:       pdclient,
		http:            httpClient,
		db:              userDB,
		mail:            mailer,
		sessions:        sessions.New(userDB, cookieKey),
		events:          events.NewManager(),
		userEmails:      make(map[string]uuid.UUID, 1024),
		userPaywallPool: make(map[uuid.UUID]paywallPoolMember, 1024),
	}

	err = p.setup()
	if err != nil {
		return nil, err
	}

	return p, nil
}

// Close performs any required shutdown and cleanup for Politeiawww.
func (p *Politeiawww) Close() {
	// Close user db connection
	p.db.Close()

	// Perform application specific shutdown
	switch p.cfg.Mode {
	case config.PoliteiaWWWMode:
		// Nothing to do
	case config.CMSWWWMode:
		p.wsDcrdata.Close()
	}
}

// Setup performs any required setup for Politeiawww.
func (p *Politeiawww) setup() error {
	// Setup email-userID cache
	err := p.initUserEmailsCache()
	if err != nil {
		return err
	}

	// Perform application specific setup
	switch p.cfg.Mode {
	case config.PoliteiaWWWMode:
		return p.setupPi()
	case config.CMSWWWMode:
		return p.setupCMS()
	default:
		return fmt.Errorf("unknown mode: %v", p.cfg.Mode)
	}
}

func (p *Politeiawww) setupPi() error {
	// Get politeiad plugins
	plugins, err := p.getPluginInventory()
	if err != nil {
		return fmt.Errorf("getPluginInventory: %v", err)
	}

	// Verify all required politeiad plugins have been registered
	required := map[string]bool{
		piplugin.PluginID: false,
		cmplugin.PluginID: false,
		tkplugin.PluginID: false,
		umplugin.PluginID: false,
	}
	for _, v := range plugins {
		_, ok := required[v.ID]
		if !ok {
			// Not a required plugin. Skip.
			continue
		}
		required[v.ID] = true
	}
	notFound := make([]string, 0, len(required))
	for pluginID, wasFound := range required {
		if !wasFound {
			notFound = append(notFound, pluginID)
		}
	}
	if len(notFound) > 0 {
		return fmt.Errorf("required politeiad plugins not found: %v", notFound)
	}

	// Setup api contexts
	recordsCtx := records.New(p.cfg, p.politeiad, p.db, p.sessions, p.events)
	commentsCtx, err := comments.New(p.cfg, p.politeiad, p.db,
		p.sessions, p.events, plugins)
	if err != nil {
		return fmt.Errorf("new comments api: %v", err)
	}
	voteCtx, err := ticketvote.New(p.cfg, p.politeiad,
		p.sessions, p.events, plugins)
	if err != nil {
		return fmt.Errorf("new ticketvote api: %v", err)
	}
	piCtx, err := pi.New(p.cfg, p.politeiad, p.db, p.mail,
		p.sessions, p.events, plugins)
	if err != nil {
		return fmt.Errorf("new pi api: %v", err)
	}

	// Setup routes
	p.setUserWWWRoutes()
	p.setPiRoutes(recordsCtx, commentsCtx, voteCtx, piCtx)

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
	err = p.initPaywallChecker()
	if err != nil {
		return err
	}

	return nil
}

func (p *Politeiawww) setupCMS() error {
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
	if errors.Is(err, cmsdatabase.ErrNoVersionRecord) ||
		errors.Is(err, cmsdatabase.ErrWrongVersion) {
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

// getPluginInventory returns the politeiad plugin inventory. If a politeiad
// connection cannot be made, the call will be retried every 5 seconds for up
// to 1000 tries.
func (p *Politeiawww) getPluginInventory() ([]pdv2.Plugin, error) {
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
