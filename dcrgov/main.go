// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"database/sql"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/decred/politeia/server"
	_ "github.com/go-sql-driver/mysql"
)

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func _main() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	log.Infof("Version : %v", cfg.Version)
	log.Infof("Home dir: %v", cfg.HomeDir)
	log.Infof("Network : %v", cfg.ChainParams.Name)

	// Setup the database connection
	var (
		connMaxLifetime = 1 * time.Minute
		maxOpenConns    = 0 // 0 is unlimited (sql package default)
		maxIdleConns    = 10

		user     = cfg.AppName
		password = cfg.DBPass
		host     = cfg.DBHost
		dbname   = fmt.Sprintf("%v_%v", cfg.AppName, cfg.ChainParams.Name)

		h = fmt.Sprintf("%v:%v@tcp(%v)/%v", user, password, host, dbname)
	)

	log.Infof("Database: %v:[pass]@tcp(%v)/%v", user, host, dbname)

	db, err := sql.Open("mysql", h)
	if err != nil {
		return err
	}

	db.SetConnMaxLifetime(connMaxLifetime)
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)

	err = db.Ping()
	if err != nil {
		return err
	}

	// Setup the app
	a, err := newAppCtx(cfg, db)
	if err != nil {
		return err
	}

	// Setup the server
	serverCfg := &server.Config{
		BuildVersion:     cfg.Version,
		HTTPSCert:        cfg.HTTPSCert,
		HTTPSKey:         cfg.HTTPSKey,
		CSRFKey:          filepath.Join(cfg.HomeDir, "csrf.key"),
		CSRFMaxAge:       60 * 60 * 24, // 1 day in seconds
		SessionKey:       filepath.Join(cfg.HomeDir, "session.key"),
		SessionMaxAge:    cfg.SessionMaxAge,
		ReadTimeout:      cfg.ReadTimeout,
		WriteTimeout:     cfg.WriteTimeout,
		ReqBodySizeLimit: cfg.ReqBodySizeLimit,
		PluginBatchLimit: cfg.PluginBatchLimit,
		Listen:           cfg.Listen,
	}
	s, err := server.New(serverCfg, db, a)
	if err != nil {
		return err
	}

	// Tell the server to start listening for requests
	listenC := make(chan error)
	s.ListenAndServeTLS(listenC)

	// Tell the user we are ready to go
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
	s.Shutdown()
	db.Close()
	return nil
}
