// Copyright (c) 2017-2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/decred/politeia/politeiawww/config"
	"github.com/decred/politeia/politeiawww/legacy"
	"github.com/decred/politeia/politeiawww/logger"
	"github.com/decred/politeia/server"
	"github.com/decred/politeia/util"
)

func _main() error {
	// Load the configuration and parse the command line. This
	// also initializes logging and configures it accordingly.
	cfg, _, err := config.Load()
	if err != nil {
		return fmt.Errorf("Could not load configuration file: %v", err)
	}
	defer func() {
		logger.CloseLogRotator()
	}()

	log.Infof("Version : %v", cfg.Version)
	log.Infof("Network : %v", cfg.ActiveNet.Name)
	log.Infof("Home dir: %v", cfg.HomeDir)

	// Check if this command is being run to fetch the politeiad
	// identity.
	if cfg.FetchIdentity {
		return getIdentity(cfg.RPCHost, cfg.RPCCert,
			cfg.RPCIdentityFile, cfg.Interactive)
	}

	// Setup politeiawww
	csrfKey, err := loadCSRF(cfg.DataDir)
	if err != nil {
		return err
	}
	router, protected := server.NewRouter(cfg.ReqBodySizeLimit,
		csrfKey, csrfMaxAge)

	p, err := legacy.NewPoliteiawww(cfg, router, protected, log)
	if err != nil {
		return err
	}

	// Bind to a port and pass our router in
	listenC := make(chan error)
	for _, listener := range cfg.Listeners {
		listen := listener
		go func() {
			tlsConfig := &tls.Config{
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
				Handler:      router,
				Addr:         listen,
				ReadTimeout:  time.Duration(cfg.ReadTimeout) * time.Second,
				WriteTimeout: time.Duration(cfg.WriteTimeout) * time.Second,
				TLSConfig:    tlsConfig,
				TLSNextProto: make(map[string]func(*http.Server,
					*tls.Conn, http.Handler)),
			}

			log.Infof("Listen: %v", listen)
			listenC <- srv.ListenAndServeTLS(cfg.HTTPSCert,
				cfg.HTTPSKey)
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

	p.Close()

	return nil
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

const (
	csrfKeyLength = 32    // In bytes
	csrfMaxAge    = 86400 // 1 day in seconds
)

// loadCSRF loads the CSRF key from disk. If a CSRF key does not exist then one
// is created and saved to disk for future use.
func loadCSRF(dataDir string) ([]byte, error) {
	log.Infof("Load CSRF key")

	// Open the CSRF key file
	fp := filepath.Join(dataDir, "csrf.key")
	fCSRF, err := os.Open(fp)
	switch {
	case err == nil:
		// CSRF key exists; continue

	case os.IsNotExist(err):
		// CSRF key does not exist. Create one
		// and save it to disk.
		key, err := util.Random(csrfKeyLength)
		if err != nil {
			return nil, err
		}

		fCSRF, err = os.OpenFile(fp, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return nil, err
		}
		_, err = fCSRF.Write(key)
		if err != nil {
			return nil, err
		}
		_, err = fCSRF.Seek(0, 0)
		if err != nil {
			return nil, err
		}

		log.Infof("CSRF key created and saved to %v", fp)

	default:
		// All other errors
		return nil, err
	}

	// Read the CSRF key from the file
	csrfKey := make([]byte, csrfKeyLength)
	r, err := fCSRF.Read(csrfKey)
	if err != nil {
		return nil, err
	}
	fCSRF.Close()

	if r != csrfKeyLength {
		return nil, fmt.Errorf("CSRF key corrupt")
	}

	return csrfKey, nil
}
