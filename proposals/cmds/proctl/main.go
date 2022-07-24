// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/jessevdk/go-flags"
	"github.com/pkg/errors"
)

var (
	// cfg is the global config object that all commands have access to.
	cfg *config

	// db is the file system key-value database that commands can use to persist
	// data.
	db *kvdb

	// log is the global log variable that commands can use to write output
	// to the log file and stdout.
	log = NewSubsystemLogger("PCTL")

	// client is a http client for interacting with the politeia API.
	client *httpc
)

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)

		// If this is a pkg/errors error then we can
		// pull the stack trace out of the error and
		// print it.
		stack, ok := stackTrace(err)
		if ok {
			fmt.Fprintf(os.Stderr, "%v\n", stack)
		}

		os.Exit(1)
	}
}

func _main() error {
	// Load the config. This also sets the global
	// cfg variable.
	var err error
	cfg, err = loadConfig()
	if err != nil {
		return errors.Errorf("load config: %v", err)
	}

	// Setup the log rotation. The log global variable may now
	// be used.
	err = InitLogRotator(filepath.Join(cfg.LogDir, logFilename))
	if err != nil {
		return err
	}
	defer CloseLogRotator()

	log.Tracef("App dir: %v", cfg.AppDir)

	// Setup the key-value database
	db, err = newKvdb(cfg.DataDir)
	if err != nil {
		return err
	}
	defer db.Close()

	// Setup the politeia http client
	opts := &httpcOpts{
		CertPool: cfg.certPool,
	}
	client, err = newHttpc(cfg.hostURL, db, opts)
	if err != nil {
		return err
	}

	// Parse the CLI args and execute the command. The help message
	// flags and unknown flag errors are caught during this parse.
	parser := flags.NewParser(&cmds{DoNotUse: cfg}, flags.Default)
	_, err = parser.Parse()
	if err != nil {
		// An error has occurred during command
		// execution. go-flags will have already
		// printed the error to os.Stdout. Exit
		// with an error code.
		os.Exit(1)
	}

	return nil
}
