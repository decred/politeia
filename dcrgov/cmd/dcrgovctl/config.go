// Copyright (c) 2013-2014 The btcsuite developers
// Copyright (c) 2015-2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/decred/dcrd/dcrutil/v3"
	"github.com/decred/politeia/util"
	"github.com/decred/slog"
	"github.com/jessevdk/go-flags"
)

const (
	// General application settings
	appName     = "dcrgovctl"
	hostAppName = "dcrgov"
	dataDirname = "data"
	logDirname  = "logs"
	logLevel    = "info"
)

var (
	// General application settings
	configFilename = fmt.Sprintf("%v.conf", appName)
	logFilename    = fmt.Sprintf("%v.log", appName)

	appDir     = dcrutil.AppDataDir(appName, false)
	dataDir    = filepath.Join(appDir, dataDirname)
	logDir     = filepath.Join(appDir, logDirname)
	configFile = filepath.Join(appDir, configFilename)

	// Server settings
	host      = "https://localhost:4443"
	hostDir   = dcrutil.AppDataDir(hostAppName, false)
	httpsCert = filepath.Join(hostDir, "https.cert")
)

// config is the command configuration.
type config struct {
	AppDir     string `long:"appdir" description:"Application home directory path"`
	DataDir    string `long:"datadir" description:"Data directory path"`
	LogDir     string `long:"logdir" description:"Log directory path"`
	ConfigFile string `long:"configfile" description:"Config file path"`
	LogLevel   string `short:"d" long:"loglevel" description:"Logging level for all subsystems {trace, debug, info, warn, error, critical} -- You may also specify <subsystem>=<level>,<subsystem2>=<level>,... to set the log level for individual subsystems -- Use show to list available subsystems"`
	Host       string `long:"host" description:"Proposals host"`
	HTTPSCert  string `long:"httpscert" description:"HTTP cert file path (for self signed certs)"`

	hostURL  *url.URL
	certPool *x509.CertPool
}

// loadConfig initializes and parses the config using a config file and command
// line options.
//
// The configuration proceeds as follows:
//  1. Start with a default config with sane settings
//  2. Pre-parse the command line to check for an alternative config file
//  3. Load configuration file overwriting defaults with any specified options
//  4. Parse CLI options and overwrite/add any specified options
//
// The above results in the app functioning properly without any config
// settings while still allowing the user to override settings with config
// files and command line options. Command line options always take precedence.
func loadConfig() (*config, error) {
	// Setup the default config
	cfg := &config{
		AppDir:     appDir,
		DataDir:    dataDir,
		LogDir:     logDir,
		ConfigFile: configFile,
		LogLevel:   logLevel,
		Host:       host,
		HTTPSCert:  httpsCert,
	}

	// Pre-parse the command line options to see if an alternative config
	// file was specified. Printing the help message and catching unknown
	// flag errors is the responsibility of the caller. The config package
	// does not have any knowledge of the commands or command descriptions,
	// which is why the help message is handled by the caller.
	var (
		preCfg    = cfg
		preParser = flags.NewParser(preCfg, flags.IgnoreUnknown)
	)
	_, err := preParser.Parse()
	if err != nil {
		return nil, err
	}

	// Update the home directory if specified. Since the home directory
	// is updated, other variables need to be updated to reflect the new
	// changes.
	if preCfg.AppDir != "" {
		cfg.AppDir = util.CleanAndExpandPath(preCfg.AppDir)

		// Update the other path config settings with the
		// newly provided application home directory.
		if preCfg.DataDir == dataDir {
			cfg.DataDir = filepath.Join(cfg.AppDir, dataDirname)
		} else {
			cfg.DataDir = preCfg.DataDir
		}
		if preCfg.LogDir == logDir {
			cfg.LogDir = filepath.Join(cfg.AppDir, logDirname)
		} else {
			cfg.LogDir = preCfg.LogDir
		}
		if preCfg.ConfigFile == configFile {
			cfg.ConfigFile = filepath.Join(cfg.AppDir, configFilename)
		} else {
			cfg.ConfigFile = preCfg.ConfigFile
		}
	}

	// Load any additional settings from the config file. Printing the help
	// message and catching unknown flag errors is the responsibility of the
	// caller. The config package does not have any knowledge of the commands
	// or command descriptions, which is why the help message is handled by
	// the caller.
	parser := flags.NewParser(cfg, flags.IgnoreUnknown|flags.PassDoubleDash)
	err = flags.NewIniParser(parser).ParseFile(cfg.ConfigFile)
	if err != nil {
		var e *os.PathError
		if !errors.As(err, &e) {
			return nil, fmt.Errorf("parse config file: %v", err)
		}
		// No config file was found. This is ok. A config file
		// is not required. Continue.
	}

	// Parse command line options again to ensure they take
	// precedence. If unknown args are found, a warning will
	// be logged once the logger has been initialized.
	_, err = parser.Parse()
	if err != nil {
		return nil, err
	}

	// Check for the show log level. This is used to list supported
	// subsystems and exit.
	if cfg.LogLevel == "show" {
		fmt.Println("Supported subsystems", SupportedSubsystems())
		os.Exit(0)
	}

	// Parse, validate, and set the log level
	err = parseAndSetLogLevels(cfg.LogLevel)
	if err != nil {
		return nil, err
	}

	// Clean and expand all file paths
	cfg.AppDir = util.CleanAndExpandPath(cfg.AppDir)
	cfg.DataDir = util.CleanAndExpandPath(cfg.DataDir)
	cfg.LogDir = util.CleanAndExpandPath(cfg.LogDir)
	cfg.ConfigFile = util.CleanAndExpandPath(cfg.ConfigFile)
	cfg.HTTPSCert = util.CleanAndExpandPath(cfg.HTTPSCert)

	// Create the app and data directories if they don't exist
	err = os.MkdirAll(cfg.AppDir, 0700)
	if err != nil {
		return nil, fmt.Errorf("create app dir: %v", err)
	}
	err = os.MkdirAll(cfg.DataDir, 0700)
	if err != nil {
		return nil, fmt.Errorf("create data dir: %v", err)
	}

	// Parse the host
	u, err := url.Parse(cfg.Host)
	if err != nil {
		return nil, err
	}
	if !u.IsAbs() {
		u.Scheme = "https"
	}
	cfg.hostURL = u

	// Setup the cert pool that will be used
	certPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	if util.FileExists(cfg.HTTPSCert) {
		cert, err := ioutil.ReadFile(cfg.HTTPSCert)
		if err != nil {
			return nil, err
		}
		certPool.AppendCertsFromPEM(cert)
	}
	cfg.certPool = certPool

	return cfg, nil
}

// parseAndSetLogLevels attempts to parse the specified log level and set
// the levels accordingly. An appropriate error is returned if anything is
// invalid.
func parseAndSetLogLevels(logLevel string) error {
	// When the specified string doesn't have any
	// delimiters, treat it as the log level for all
	// subsystems.
	if !strings.Contains(logLevel, ",") &&
		!strings.Contains(logLevel, "=") {
		// Validate log level
		if !validLogLevel(logLevel) {
			return fmt.Errorf("the specified log level "+
				"[%v] is invalid", logLevel)
		}

		// Change the logging level for all subsystems
		SetLogLevels(logLevel)

		return nil
	}

	// Split the specified string into subsystem/level pairs while
	// detecting issues and update the log levels accordingly.
	for _, logLevelPair := range strings.Split(logLevel, ",") {
		if !strings.Contains(logLevelPair, "=") {
			str := "The specified log level contains an invalid " +
				"subsystem/level pair [%v]"
			return fmt.Errorf(str, logLevelPair)
		}

		// Extract the specified subsystem and log level
		fields := strings.Split(logLevelPair, "=")
		subsysID, logLevel := fields[0], fields[1]

		// Validate subsystem
		subsystems := make(map[string]struct{})
		for _, v := range SupportedSubsystems() {
			subsystems[v] = struct{}{}
		}
		if _, exists := subsystems[subsysID]; !exists {
			str := "The specified subsystem [%v] is invalid -- " +
				"supported subsytems %v"
			return fmt.Errorf(str, subsysID, SupportedSubsystems())
		}

		// Validate log level
		if !validLogLevel(logLevel) {
			str := "The specified log level [%v] is invalid"
			return fmt.Errorf(str, logLevel)
		}

		SetLogLevel(subsysID, logLevel)
	}

	return nil
}

// validLogLevel returns whether the logLevel is a valid log level.
func validLogLevel(logLevel string) bool {
	_, ok := slog.LevelFromString(logLevel)
	return ok
}
