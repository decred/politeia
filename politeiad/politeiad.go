// Copyright (c) 2017-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/decred/dcrd/chaincfg/v3"
	v1 "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	v2 "github.com/decred/politeia/politeiad/api/v2"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/gitbe"
	"github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe"
	"github.com/decred/politeia/util"
	"github.com/decred/politeia/util/version"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
)

type permission uint

const (
	permissionPublic permission = iota
	permissionAuth
)

// politeia application context.
type politeia struct {
	backend   backend.Backend
	backendv2 backendv2.Backend
	cfg       *config
	router    *mux.Router
	identity  *identity.FullIdentity
}

func remoteAddr(r *http.Request) string {
	via := r.RemoteAddr
	xff := r.Header.Get(v1.Forward)
	if xff != "" {
		return fmt.Sprintf("%v via %v", xff, r.RemoteAddr)
	}
	return via
}

// handleNotFound is a generic handler for an invalid route.
func (p *politeia) handleNotFound(w http.ResponseWriter, r *http.Request) {
	// Log incoming connection
	log.Debugf("Invalid route: %v %v %v %v", remoteAddr(r), r.Method, r.URL,
		r.Proto)

	// Trace incoming request
	log.Tracef("%v", newLogClosure(func() string {
		trace, err := httputil.DumpRequest(r, true)
		if err != nil {
			trace = []byte(fmt.Sprintf("logging: "+
				"DumpRequest %v", err))
		}
		return string(trace)
	}))

	util.RespondWithJSON(w, http.StatusNotFound, v1.ServerErrorReply{})
}

func (p *politeia) respondWithUserError(w http.ResponseWriter, errorCode v1.ErrorStatusT, errorContext []string) {
	util.RespondWithJSON(w, http.StatusBadRequest, v1.UserErrorReply{
		ErrorCode:    errorCode,
		ErrorContext: errorContext,
	})
}

func (p *politeia) respondWithServerError(w http.ResponseWriter, errorCode int64, err error) {
	// If this is a pkg/errors error then we can pull the
	// stack trace out of the error, otherwise, we use the
	// stack trace for this function.
	stack, ok := util.StackTrace(err)
	if !ok {
		stack = string(debug.Stack())
	}

	log.Errorf("Stacktrace (NOT A REAL CRASH): %v", stack)

	util.RespondWithJSON(w, http.StatusInternalServerError, v1.ServerErrorReply{
		ErrorCode: errorCode,
	})
}

func (p *politeia) check(user, pass string) bool {
	if user != p.cfg.RPCUser || pass != p.cfg.RPCPass {
		return false
	}
	return true
}

func (p *politeia) auth(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || !p.check(user, pass) {
			log.Infof("%v Unauthorized access for: %v",
				remoteAddr(r), user)
			w.Header().Set("WWW-Authenticate",
				`Basic realm="Politeiad"`)
			w.WriteHeader(401)
			p.respondWithUserError(w, v1.ErrorStatusInvalidRPCCredentials, nil)
			return
		}
		log.Infof("%v Authorized access for: %v",
			remoteAddr(r), user)
		fn(w, r)
	}
}

func logging(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Trace incoming request
		log.Tracef("%v", newLogClosure(func() string {
			trace, err := httputil.DumpRequest(r, true)
			if err != nil {
				trace = []byte(fmt.Sprintf("logging: "+
					"DumpRequest %v", err))
			}
			return string(trace)
		}))

		// Log incoming connection
		log.Infof("%v %v %v %v", remoteAddr(r), r.Method, r.URL, r.Proto)
		f(w, r)
	}
}

// closeBody closes the request body after the provided handler is called.
func closeBody(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f(w, r)
		r.Body.Close()
	}
}

func (p *politeia) addRoute(method string, route string, handler http.HandlerFunc, perm permission) {
	if perm == permissionAuth {
		handler = p.auth(handler)
	}
	handler = closeBody(logging(handler))

	p.router.StrictSlash(true).HandleFunc(route, handler).Methods(method)
}

func (p *politeia) addRouteV2(method string, route string, handler http.HandlerFunc, perm permission) {
	route = v2.APIRoute + route
	p.addRoute(method, route, handler, perm)
}

func (p *politeia) setupBackendGit(anp *chaincfg.Params) error {
	b, err := gitbe.New(activeNetParams.Params, p.cfg.DataDir,
		p.cfg.DcrtimeHost, "", p.identity, p.cfg.GitTrace, p.cfg.DcrdataHost)
	if err != nil {
		return fmt.Errorf("new gitbe: %v", err)
	}
	p.backend = b

	// Setup mux
	p.router = mux.NewRouter()

	// Not found
	p.router.NotFoundHandler = closeBody(p.handleNotFound)

	// Unprivileged routes
	p.addRoute(http.MethodPost, v1.IdentityRoute, p.getIdentity,
		permissionPublic)
	p.addRoute(http.MethodPost, v1.NewRecordRoute, p.newRecord,
		permissionPublic)
	p.addRoute(http.MethodPost, v1.UpdateUnvettedRoute, p.updateUnvetted,
		permissionPublic)
	p.addRoute(http.MethodPost, v1.UpdateVettedRoute, p.updateVetted,
		permissionPublic)
	p.addRoute(http.MethodPost, v1.GetUnvettedRoute, p.getUnvetted,
		permissionPublic)
	p.addRoute(http.MethodPost, v1.GetVettedRoute, p.getVetted,
		permissionPublic)

	// Routes that require auth
	p.addRoute(http.MethodPost, v1.InventoryRoute, p.inventory,
		permissionAuth)
	p.addRoute(http.MethodPost, v1.SetUnvettedStatusRoute,
		p.setUnvettedStatus, permissionAuth)
	p.addRoute(http.MethodPost, v1.SetVettedStatusRoute,
		p.setVettedStatus, permissionAuth)
	p.addRoute(http.MethodPost, v1.UpdateVettedMetadataRoute,
		p.updateVettedMetadata, permissionAuth)

	// Set plugin routes. Requires auth.
	p.addRoute(http.MethodPost, v1.PluginCommandRoute, p.pluginCommand,
		permissionAuth)
	p.addRoute(http.MethodPost, v1.PluginInventoryRoute, p.pluginInventory,
		permissionAuth)

	return nil
}

// parsePluginSetting parses a politeiad config plugin setting. Plugin settings
// will be in following format. The value may be a single value of an array of
// values.
//
// "pluginID,key,value"
// "pluginID,key,[value1,value2,value3...]"
//
// When multiple values are provided, the values are parsed and returned as a
// JSON encoded []string. Plugins should expect to receive the JSON.
func parsePluginSetting(setting string) (string, *backendv2.PluginSetting, error) {
	formatMsg := "expected plugin setting format is " +
		"'pluginID,key,value' or 'pluginID,key,[value1,value2,value3...]'"

	// A plugin setting will be a comma separated list containing
	// at least two commas, but possibly more.
	if strings.Count(setting, ",") < 2 {
		return "", nil, errors.Errorf("invalid format '%v'; %v",
			setting, formatMsg)
	}

	// Clean setting
	setting = strings.ToLower(setting)
	setting = strings.TrimSpace(setting)

	// Find the indexes of the commas
	var (
		comma1 int
		comma2 int
	)
	for i, v := range setting {
		if string(v) != "," {
			continue
		}
		switch {
		case comma1 == 0:
			comma1 = i
		case comma2 == 0:
			comma2 = i
		}
		if comma2 != 0 {
			// We're done
			break
		}
	}

	// Parse the plugin setting
	var (
		pluginID     = strings.TrimSpace(setting[0:comma1])
		settingKey   = strings.TrimSpace(setting[comma1+1 : comma2])
		settingValue = strings.TrimSpace(setting[comma2+1:])
	)
	switch {
	case len(pluginID) == 0:
		return "", nil, errors.Errorf("plugin id not found in '%v'; %v",
			setting, formatMsg)
	case len(settingKey) == 0:
		return "", nil, errors.Errorf("setting key not found in '%v'; %v",
			setting, formatMsg)
	case len(settingValue) == 0:
		return "", nil, errors.Errorf("setting value not found in '%v'; %v",
			setting, formatMsg)
	}

	// The setting value can either be a single value or multiple
	// values. Multiple values are parsed and returned as a JSON
	// array. Plugins should expect to receive a JSON array.
	if strings.Index(settingValue, "[") == 0 {
		// This setting value contains multiple values. Verify that
		// it has a closing bracket.
		if strings.LastIndex(settingValue, "]") != len(settingValue)-1 {
			return "", nil, errors.Errorf("invalid setting value; "+
				"expected to find a closing ']' in '%v'; %v",
				settingValue, formatMsg)
		}

		// Trim opening and closing brackets
		settingValue = settingValue[1 : len(settingValue)-1]

		// Parse the values. We do this manually in case the setting
		// value contains an escaped comma, indicating that the
		// comma is the value itself and not a list item separator.
		var (
			values   = make([]string, 0, 256)
			startIdx int
			escaped  bool
		)
		for i, v := range settingValue {
			switch {
			case escaped:
				// This character is escaped. Reset escaped
				// and continue.
				escaped = false
				continue
			case string(v) == `\`:
				// Escaped character found
				escaped = true
				continue
			case string(v) != ",":
				continue
			}

			// This is a comma. Parse the preceding value.
			value := settingValue[startIdx:i]
			values = append(values, value)
			startIdx = i + 1
		}

		// Add the last value to the list
		values = append(values, settingValue[startIdx:])

		// Update settingValue to its JSON encoded equivalent
		b, err := json.Marshal(values)
		if err != nil {
			return "", nil, err
		}
		settingValue = string(b)
	}

	return pluginID, &backendv2.PluginSetting{
		Key:   settingKey,
		Value: settingValue,
	}, nil
}

func (p *politeia) setupBackendTstore(anp *chaincfg.Params) error {
	b, err := tstorebe.New(p.cfg.HomeDir, p.cfg.DataDir, anp,
		p.cfg.TlogHost, p.cfg.TlogPass, p.cfg.DBType, p.cfg.DBHost,
		p.cfg.DBPass, p.cfg.DcrtimeHost, p.cfg.DcrtimeCert)
	if err != nil {
		return fmt.Errorf("new tstorebe: %v", err)
	}
	p.backendv2 = b

	// Setup mux
	p.router = mux.NewRouter()

	// Setup not found handler
	p.router.NotFoundHandler = closeBody(p.handleNotFound)

	// Setup v1 routes
	p.addRoute(http.MethodPost, v1.IdentityRoute,
		p.getIdentity, permissionPublic)

	// Setup v2 routes
	p.addRouteV2(http.MethodPost, v2.RouteRecordNew,
		p.handleRecordNew, permissionPublic)
	p.addRouteV2(http.MethodPost, v2.RouteRecordEdit,
		p.handleRecordEdit, permissionPublic)
	p.addRouteV2(http.MethodPost, v2.RouteRecordEditMetadata,
		p.handleRecordEditMetadata, permissionPublic)
	p.addRouteV2(http.MethodPost, v2.RouteRecordSetStatus,
		p.handleRecordSetStatus, permissionPublic)
	p.addRouteV2(http.MethodPost, v2.RouteRecords,
		p.handleRecords, permissionPublic)
	p.addRouteV2(http.MethodPost, v2.RouteRecordTimestamps,
		p.handleRecordTimestamps, permissionPublic)
	p.addRouteV2(http.MethodPost, v2.RouteInventory,
		p.handleInventory, permissionPublic)
	p.addRouteV2(http.MethodPost, v2.RouteInventoryOrdered,
		p.handleInventoryOrdered, permissionPublic)
	p.addRouteV2(http.MethodPost, v2.RoutePluginWrite,
		p.handlePluginWrite, permissionPublic)
	p.addRouteV2(http.MethodPost, v2.RoutePluginReads,
		p.handlePluginReads, permissionPublic)
	p.addRouteV2(http.MethodPost, v2.RoutePluginInventory,
		p.handlePluginInventory, permissionPublic)

	p.addRouteV2(http.MethodPost, v2.RoutePluginInventory,
		p.handlePluginInventory, permissionPublic)

	// Setup plugins
	if len(p.cfg.Plugins) > 0 {
		// Parse plugin settings
		settings := make(map[string][]backendv2.PluginSetting)
		for _, v := range p.cfg.PluginSettings {
			// Parse plugin setting
			pluginID, ps, err := parsePluginSetting(v)
			if err != nil {
				return err
			}

			// Add to settings list
			pss, ok := settings[pluginID]
			if !ok {
				pss = make([]backendv2.PluginSetting, 0, 16)
			}
			pss = append(pss, *ps)

			// Save settings list
			settings[pluginID] = pss
		}

		// Register plugins
		for _, v := range p.cfg.Plugins {
			// Setup plugin
			ps, ok := settings[v]
			if !ok {
				ps = make([]backendv2.PluginSetting, 0)
			}
			plugin := backendv2.Plugin{
				ID:       v,
				Settings: ps,
				Identity: p.identity,
			}

			// Register plugin
			log.Infof("Register plugin: %v", v)
			err = p.backendv2.PluginRegister(plugin)
			if err != nil {
				return fmt.Errorf("PluginRegister %v: %v", v, err)
			}
		}

		// Setup plugins
		for _, v := range p.backendv2.PluginInventory() {
			log.Infof("Setup plugin: %v", v.ID)
			err = p.backendv2.PluginSetup(v.ID)
			if err != nil {
				return fmt.Errorf("plugin setup %v: %v", v.ID, err)
			}
		}
	}

	return nil
}

func _main() error {
	// Load configuration and parse command line.  This function also
	// initializes logging and configures it accordingly.
	cfg, _, err := loadConfig()
	if err != nil {
		return fmt.Errorf("Could not load configuration file: %v", err)
	}
	defer func() {
		if logRotator != nil {
			logRotator.Close()
		}
	}()

	log.Infof("Version : %v", version.String())
	log.Infof("Build   : %v", version.BuildMainVersion())
	log.Infof("Network : %v", activeNetParams.Params.Name)
	log.Infof("Home dir: %v", cfg.HomeDir)

	// Create the data directory in case it does not exist.
	err = os.MkdirAll(cfg.DataDir, 0700)
	if err != nil {
		return err
	}

	// Generate the TLS cert and key file if both don't already
	// exist.
	if !util.FileExists(cfg.HTTPSKey) &&
		!util.FileExists(cfg.HTTPSCert) {
		log.Infof("Generating HTTPS keypair...")

		err := util.GenCertPair(elliptic.P521(), "politeiad",
			cfg.HTTPSCert, cfg.HTTPSKey)
		if err != nil {
			return fmt.Errorf("unable to create https keypair: %v",
				err)
		}

		log.Infof("HTTPS keypair created...")
	}

	// Generate ed25519 identity to save messages, tokens etc.
	if !util.FileExists(cfg.Identity) {
		log.Infof("Generating signing identity...")
		id, err := identity.New()
		if err != nil {
			return err
		}
		err = id.Save(cfg.Identity)
		if err != nil {
			return err
		}
		log.Infof("Signing identity created...")
	}

	// Setup application context.
	p := &politeia{
		cfg: cfg,
	}

	// Load identity.
	p.identity, err = identity.LoadFullIdentity(cfg.Identity)
	if err != nil {
		return err
	}
	log.Infof("Public key: %x", p.identity.Public.Key)

	// Load certs, if there.  If they aren't there assume OS is used to
	// resolve cert validity.
	if len(cfg.DcrtimeCert) != 0 {
		var certPool *x509.CertPool
		if !util.FileExists(cfg.DcrtimeCert) {
			return fmt.Errorf("unable to find dcrtime cert %v",
				cfg.DcrtimeCert)
		}
		dcrtimeCert, err := ioutil.ReadFile(cfg.DcrtimeCert)
		if err != nil {
			return fmt.Errorf("unable to read dcrtime cert %v: %v",
				cfg.DcrtimeCert, err)
		}
		certPool = x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(dcrtimeCert) {
			return fmt.Errorf("unable to load cert")
		}
	}

	// Setup backend
	log.Infof("Backend: %v", cfg.Backend)
	switch cfg.Backend {
	case backendGit:
		err := p.setupBackendGit(activeNetParams.Params)
		if err != nil {
			return err
		}
	case backendTstore:
		err := p.setupBackendTstore(activeNetParams.Params)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid backend selected: %v", cfg.Backend)
	}

	// Bind to a port and pass our router in
	listenC := make(chan error)
	for _, listener := range cfg.Listeners {
		listen := listener
		go func() {
			log.Infof("Listen: %v", listen)
			listenC <- http.ListenAndServeTLS(listen,
				cfg.HTTPSCert, cfg.HTTPSKey, p.router)
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
	switch p.cfg.Backend {
	case backendGit:
		p.backend.Close()
	case backendTstore:
		p.backendv2.Close()
	}

	log.Infof("Exiting")

	return nil
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
