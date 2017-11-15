package main

import (
	"context"
	"crypto/elliptic"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/decred/politeia/util"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
)

func main() {
	if err := _main(); err != nil {
		//@TODO (rgeraldes)
		//log.Error()
	}
}

func _main() error {
	cfg, _, err := loadConfig()
	if err != nil {
		return fmt.Errorf("Could not load configuration file: %v", err)
	}

	log.Infof("Version : %v", version())
	log.Infof("Network : %v", activeNetParams.Params.Name)
	log.Infof("Home dir: %v", cfg.HomeDir)

	// @TODO(rgeraldes) need to verify this one
	defer func() {
		if logRotator != nil {
			logRotator.Close()
		}
	}()

	// TLS certificate
	if err := generateTLSCertificate(cfg); err != nil {
		return err
	}

	// create router, server & register server handlers
	router := mux.NewRouter().StrictSlash(true)
	politeia, err := NewPoliteiaWWW(cfg)
	if err != nil {
		return err
	}

	// @TODO - rgeraldes - add as a sub command?
	// Check if this command is being run to fetch the identity.
	if cfg.FetchIdentity {
		return politeia.getIdentity()
	}

	// register politeiaWWW routes
	politeia.RegisterHandlers(router)

	// cross site request forgery handler
	var csrfHandler func(http.Handler) http.Handler
	if !cfg.Proxy {
		// We don't persist connections to generate a new key every
		// time we restart.
		csrfKey, err := util.Random(32)
		if err != nil {
			return err
		}
		csrfHandler = csrf.Protect(csrfKey)
	}

	// listen for errors from ListenAndServeTLS
	listenerC := make(chan error, 1)
	// list of http servers used for the graceful shutdown
	servers := make([]*http.Server, len(cfg.Listeners))

	for _, listener := range cfg.Listeners {
		addr := listener

		srv := &http.Server{
			Addr:      addr,
			TLSConfig: defaultTSLConfig,
			TLSNextProto: make(map[string]func(*http.Server,
				*tls.Conn, http.Handler)),
		}

		servers = append(servers, srv)

		go func() {
			var mode string
			if cfg.Proxy {
				srv.Handler = router
				mode = "proxy"
			} else {
				srv.Handler = csrfHandler(router)
				mode = "non-proxy"
			}

			log.Infof("Listen %v: %v", mode, addr)
			listenerC <- srv.ListenAndServeTLS(cfg.HTTPSCert,
				cfg.HTTPSKey)
		}()
	}

	signalC := make(chan os.Signal, 1)
	signal.Notify(signalC, os.Interrupt, syscall.SIGTERM)

	// wait for signals/http servers' unexpected error
L:
	for {
		select {
		case signal := <-signalC:
			log.Info(signal)
			break L
		case err := <-listenerC:
			log.Error(err)
			break L
		}
	}

	gracefulShutdown(servers)
	log.Infof("Exiting")

	return nil
}

// generateTLSCertificate generates the TLS certificate if necessary
func generateTLSCertificate(cfg *config) error {
	if !fileExists(cfg.HTTPSKey) &&
		!fileExists(cfg.HTTPSCert) {
		log.Infof("Generating HTTPS keypair...")

		err := util.GenCertPair(elliptic.P256(), "politeiadwww",
			cfg.HTTPSCert, cfg.HTTPSKey)
		if err != nil {
			return fmt.Errorf("unable to create https keypair: %v",
				err)
		}

		log.Infof("HTTPS keypair created...")
	}
	return nil
}

// gracefulShutdown terminates the listeners gracefully
func gracefulShutdown(servers []*http.Server) {
	// graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, srv := range servers {
		if err := srv.Shutdown(ctx); err != nil {
			log.Error(err)
		}
	}
}
