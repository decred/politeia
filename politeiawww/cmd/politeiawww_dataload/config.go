// Copyright (c) 2013-2014 The btcsuite developers
// Copyright (c) 2015-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/thi4go/politeia/politeiawww/sharedconfig"
	flags "github.com/jessevdk/go-flags"
)

const (
	defaultDataDirname            = "dataload"
	defaultConfigFilename         = "politeiawww_dataload.conf"
	defaultPoliteiadLogFilename   = "politeiad.log"
	defaultPoliteiawwwLogFilename = "politeiawww.log"
	defaultLogLevel               = "info"
)

var (
	defaultDataDir    = filepath.Join(sharedconfig.DefaultHomeDir, defaultDataDirname)
	defaultConfigFile = filepath.Join(defaultDataDir, defaultConfigFilename)
)

// config defines the configuration options for politeiawww_dataload.
//
// See loadConfig for details on the configuration load process.
type config struct {
	AdminEmail          string `long:"adminemail" description:"Admin user email address"`
	AdminUser           string `long:"adminuser" description:"Admin username"`
	AdminPass           string `long:"adminpass" description:"Admin password"`
	PaidEmail           string `long:"paidemail" description:"Regular paid user email address"`
	PaidUser            string `long:"paiduser" description:"Regular paid user username"`
	PaidPass            string `long:"paidpass" description:"Regular paid user password"`
	UnpaidEmail         string `long:"unpaidemail" description:"Regular unpaid user email address"`
	UnpaidUser          string `long:"unpaiduser" description:"Regular unpaid user username"`
	UnpaidPass          string `long:"unpaidpass" description:"Regular unpaid user password"`
	VettedPropsNumber   int    `long:"vettedproposalsnumber" description:"Number of vetted proposals to be created"`
	UnvettedPropsNumber int    `long:"unvettedproposalsnumber" description:"Number of unvetted proposals to be created"`
	CommentsNumber      int    `long:"commentsnumber" description:"Number of comments on the firs vetted proposal"`
	Verbose             bool   `short:"v" long:"verbose" description:"Verbose output"`
	DataDir             string `long:"datadir" description:"Path to config/data directory"`
	ConfigFile          string `long:"configfile" description:"Path to configuration file"`
	DebugLevel          string `long:"debuglevel" description:"Logging level to use for servers {trace, debug, info, warn, error, critical}"`
	DeleteData          bool   `long:"deletedata" description:"Delete all existing data from politeiad and politeiawww before loading data"`
	PoliteiadLogFile    string
	PoliteiawwwLogFile  string
}

// cleanAndExpandPath expands environment variables and leading ~ in the
// passed path, cleans the result, and returns it.
func cleanAndExpandPath(path string) string {
	// Expand initial ~ to OS specific home directory.
	if strings.HasPrefix(path, "~") {
		homeDir := filepath.Dir(sharedconfig.DefaultHomeDir)
		path = strings.Replace(path, "~", homeDir, 1)
	}

	// NOTE: The os.ExpandEnv doesn't work with Windows-style %VARIABLE%,
	// but the variables can still be expanded via POSIX-style $VARIABLE.
	return filepath.Clean(os.ExpandEnv(path))
}

// newConfigParser returns a new command line flags parser.
func newConfigParser(cfg *config, options flags.Options) *flags.Parser {
	return flags.NewParser(cfg, options)
}

// loadConfig initializes and parses the config using a config file and command
// line options.
//
// The configuration proceeds as follows:
// 	1) Start with a default config with sane settings
// 	2) Pre-parse the command line to check for an alternative config file
// 	3) Load configuration file overwriting defaults with any specified options
// 	4) Parse CLI options and overwrite/add any specified options
//
// The above results in rpc functioning properly without any config settings
// while still allowing the user to override settings with config files and
// command line options.  Command line options always take precedence.
func loadConfig() (*config, error) {
	// Default config.
	cfg := config{
		AdminEmail:          "admin@example.com",
		AdminUser:           "admin",
		AdminPass:           "password",
		PaidEmail:           "paid_user@example.com",
		PaidUser:            "paid_user",
		PaidPass:            "password",
		UnpaidEmail:         "unpaid_user@example.com",
		UnpaidUser:          "unpaid_user",
		UnpaidPass:          "password",
		VettedPropsNumber:   1,
		UnvettedPropsNumber: 2,
		CommentsNumber:      2,
		DeleteData:          false,
		Verbose:             false,
		DataDir:             defaultDataDir,
		ConfigFile:          defaultConfigFile,
		DebugLevel:          defaultLogLevel,
	}

	// Pre-parse the command line options to see if an alternative config
	// file or the version flag was specified.  Any errors aside from the
	// help message error can be ignored here since they will be caught by
	// the final parse below.
	preCfg := cfg
	preParser := newConfigParser(&preCfg, flags.HelpFlag)
	_, err := preParser.Parse()
	if err != nil {
		if e, ok := err.(*flags.Error); ok && e.Type == flags.ErrHelp {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(0)
		}
	}

	// Show the version and exit if the version flag was specified.
	appName := filepath.Base(os.Args[0])
	appName = strings.TrimSuffix(appName, filepath.Ext(appName))
	usageMessage := fmt.Sprintf("Use %s -h to show usage", appName)

	// Update the data directory if specified. Since the data directory
	// is updated, other variables need to be updated to reflect the new changes.
	if preCfg.DataDir != "" {
		cfg.DataDir, _ = filepath.Abs(preCfg.DataDir)

		if preCfg.ConfigFile == defaultConfigFile {
			cfg.ConfigFile = filepath.Join(cfg.DataDir, defaultConfigFilename)
		} else {
			cfg.ConfigFile = cleanAndExpandPath(preCfg.ConfigFile)
		}
	}

	// Load additional config from file.
	var configFileError error
	parser := newConfigParser(&cfg, flags.Default)
	err = flags.NewIniParser(parser).ParseFile(cfg.ConfigFile)
	if err != nil {
		if _, ok := err.(*os.PathError); !ok {
			fmt.Fprintf(os.Stderr, "Error parsing config "+
				"file: %v\n", err)
			fmt.Fprintln(os.Stderr, usageMessage)
			return nil, err
		}
		configFileError = err
	}

	// Parse command line options again to ensure they take precedence.
	_, err = parser.Parse()
	if err != nil {
		if e, ok := err.(*flags.Error); !ok || e.Type != flags.ErrHelp {
			fmt.Fprintln(os.Stderr, usageMessage)
		}
		return nil, err
	}

	// Create the data directory if it doesn't already exist.
	funcName := "loadConfig"
	err = os.MkdirAll(cfg.DataDir, 0700)
	if err != nil {
		// Show a nicer error message if it's because a symlink is
		// linked to a directory that does not exist (probably because
		// it's not mounted).
		if e, ok := err.(*os.PathError); ok && os.IsExist(err) {
			if link, lerr := os.Readlink(e.Path); lerr == nil {
				str := "is symlink %s -> %s mounted?"
				err = fmt.Errorf(str, e.Path, link)
			}
		}

		str := "%s: Failed to create data directory: %v"
		err := fmt.Errorf(str, funcName, err)
		fmt.Fprintln(os.Stderr, err)
		return nil, err
	}

	if configFileError != nil {
		fmt.Printf("WARNING: %v\n", configFileError)
	}

	cfg.PoliteiadLogFile = filepath.Join(cfg.DataDir,
		defaultPoliteiadLogFilename)
	cfg.PoliteiawwwLogFile = filepath.Join(cfg.DataDir,
		defaultPoliteiawwwLogFilename)

	return &cfg, nil
}
