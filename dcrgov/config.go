// Copyright (c) 2013-2016 The btcsuite developers
// Copyright (c) 2015-2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/dcrutil/v3"
	"github.com/decred/politeia/app"
	"github.com/decred/politeia/dcrgov/version"
	"github.com/decred/politeia/politeiawww/logger"
	"github.com/decred/politeia/util"
	"github.com/decred/slog"
	"github.com/jessevdk/go-flags"
	"github.com/pkg/errors"
)

var (
	// General application defaults
	appName            = "dcrgov"
	defaultDataDirname = "data"
	defaultLogDirname  = "logs"
	defaultLogLevel    = "info"

	defaultConfigFilename = fmt.Sprintf("%v.conf", appName)
	defaultLogFilename    = fmt.Sprintf("%v.log", appName)

	defaultHomeDir    = dcrutil.AppDataDir(appName, false)
	defaultConfigFile = filepath.Join(defaultHomeDir, defaultConfigFilename)
	defaultDataDir    = filepath.Join(defaultHomeDir, defaultDataDirname)
	defaultLogDir     = filepath.Join(defaultHomeDir, defaultLogDirname)

	// HTTP server defaults
	defaultHTTPSCertFilename        = "https.cert"
	defaultHTTPSKeyFilename         = "https.key"
	defaultSessionMaxAge     uint32 = 60 * 60 * 24    // 1 day in seconds
	defaultReadTimeout       uint32 = 5               // In seconds
	defaultWriteTimeout      uint32 = 60              // In seconds
	defaultReqBodySizeLimit  int64  = 3 * 1024 * 1024 // 3 MiB
	defaultPluginBatchLimit  uint32 = 20
	defaultListen                   = "4443"

	defaultHTTPSCert = filepath.Join(defaultHomeDir, defaultHTTPSCertFilename)
	defaultHTTPSKey  = filepath.Join(defaultHomeDir, defaultHTTPSKeyFilename)

	// Database settings
	defaultMySQLHost = "localhost:3306"

	// Environmental variables that are used to pass in config settings
	envDBPass = "DBPASS"
)

// config defines the configuration options for the proposals app.
//
// See the loadConfig function for details on the configuration load process.
type config struct {
	// General application settings
	ShowVersion bool   `short:"V" long:"version" description:"Display version information and exit"`
	HomeDir     string `short:"A" long:"appdata" description:"Path to application home directory"`
	ConfigFile  string `short:"C" long:"configfile" description:"Path to configuration file"`
	DataDir     string `short:"b" long:"datadir" description:"Directory to store data"`
	LogDir      string `long:"logdir" description:"Directory to log output"`
	DebugLevel  string `short:"d" long:"debuglevel" description:"Logging level for all subsystems {trace, debug, info, warn, error, critical} -- You may also specify <subsystem>=<level>,<subsystem2>=<level>,... to set the log level for individual subsystems -- Use show to list available subsystems"`

	// Network settings
	TestNet bool `long:"testnet" description:"Use the decred test network"`

	// HTTP server settings
	Listen           string `long:"listen" description:"Port that the http server will listen on"`
	HTTPSCert        string `long:"httpscert" description:"HTTPS certificate file path"`
	HTTPSKey         string `long:"httpskey" description:"HTTPS certificate key path"`
	SessionMaxAge    uint32 `long:"sessionmaxage" description:"Max age of a session in seconds"`
	ReadTimeout      uint32 `long:"readtimeout" description:"Max duration in seconds that is spent reading the request headers and body"`
	WriteTimeout     uint32 `long:"writetimeout" description:"Max duration in seconds that a request connection is kept open"`
	ReqBodySizeLimit int64  `long:"reqbodysizelimit" description:"Max number of bytes allowed in a request body submitted by a client"`
	PluginBatchLimit uint32 `long:"pluginbatchlimit" description:"Max number of plugins command allowed in a batch request."`

	// Database settings
	DBHost string `long:"dbhost" description:"Database host"`
	DBPass string // Provided in env variable "DBPASS"

	// Plugin settings
	RawPluginSettings []string `long:"pluginsetting" description:"Plugin setting formatted as '[pluginID],[settingName],[settingValue]'"`

	// Cooked options ready for use
	AppName        string
	Version        string
	ChainParams    *chaincfg.Params
	SystemCerts    *x509.CertPool
	PluginSettings map[string][]app.Setting // [pluginID][]Setting
}

// loagConfig initializes and parses the config using a config file and command
// line options.
//
// The configuration proceeds as follows:
//  1. Start with a default config with sane settings.
//  2. Pre-parse the command line to check for an alternative config file.
//  3. Load the configuration file, overwriting defaults with any specified
//     options.
//  4. Parse the CLI options and overwrite/add any specified options.
//
// The above results in the server functioning properly without any config
// settings while still allowing the user to override settings with config
// files and command line options. Command line options always take precedence.
//
// This functions intializes the log rotater. It is the responsibility of the
// caller to close the log rotater.
func loadConfig() (*config, error) {
	// Setup the default configuration
	cfg := &config{
		// General application defaults
		ShowVersion: false,
		HomeDir:     defaultHomeDir,
		ConfigFile:  defaultConfigFile,
		DataDir:     defaultDataDir,
		LogDir:      defaultLogDir,
		DebugLevel:  defaultLogLevel,

		// Network defaults
		TestNet: false,

		// HTTP server defaults
		Listen:           defaultListen,
		HTTPSCert:        defaultHTTPSCert,
		HTTPSKey:         defaultHTTPSKey,
		SessionMaxAge:    defaultSessionMaxAge,
		ReadTimeout:      defaultReadTimeout,
		WriteTimeout:     defaultWriteTimeout,
		ReqBodySizeLimit: defaultReqBodySizeLimit,
		PluginBatchLimit: defaultPluginBatchLimit,

		// Database defaults
		DBHost: defaultMySQLHost,

		// Cooked options ready for use
		AppName:     appName,
		Version:     version.Version,
		ChainParams: chaincfg.MainNetParams(),
	}

	// Pre-parse the command line options to see if an alternative config
	// file or the version flag was specified. Any errors aside from the
	// help message error can be ignored here since they will be caught by
	// the final parse below.
	preCfg := cfg
	preParser := flags.NewParser(preCfg, flags.HelpFlag)
	_, err := preParser.Parse()
	if err != nil {
		var e *flags.Error
		if errors.As(err, &e) {
			if e.Type != flags.ErrHelp {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Fprintln(os.Stdout, err)
			os.Exit(0)
		}
	}

	// Show the version and exit if the version flag was specified.
	if preCfg.ShowVersion {
		fmt.Printf("%s version %s (Go version %s %s/%s)\n", cfg.AppName,
			cfg.Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	// Update the home directory if specified. Since the home directory is
	// updated, other file paths need to be updated to reflect the updated
	// home directory.
	if preCfg.HomeDir != "" {
		cfg.HomeDir = util.CleanAndExpandPath(preCfg.HomeDir)

		// Update the other path config settings with the newly
		// provided application home directory.
		if preCfg.DataDir == defaultDataDir {
			cfg.DataDir = filepath.Join(cfg.HomeDir, defaultDataDirname)
		} else {
			cfg.DataDir = preCfg.DataDir
		}
		if preCfg.LogDir == defaultLogDir {
			cfg.LogDir = filepath.Join(cfg.HomeDir, defaultLogDirname)
		} else {
			cfg.LogDir = preCfg.LogDir
		}
		if preCfg.ConfigFile == defaultConfigFile {
			cfg.ConfigFile = filepath.Join(cfg.HomeDir, defaultConfigFilename)
		} else {
			cfg.ConfigFile = preCfg.ConfigFile
		}
		if preCfg.HTTPSCert == defaultHTTPSCert {
			cfg.HTTPSCert = filepath.Join(cfg.HomeDir, defaultHTTPSCertFilename)
		} else {
			cfg.HTTPSCert = preCfg.HTTPSCert
		}
		if preCfg.HTTPSKey == defaultHTTPSKey {
			cfg.HTTPSKey = filepath.Join(cfg.HomeDir, defaultHTTPSKeyFilename)
		} else {
			cfg.HTTPSKey = preCfg.HTTPSKey
		}
	}

	// Create a default config file when one does not
	// exist and the user did not specify an override.
	if preCfg.ConfigFile == defaultConfigFile &&
		!util.FileExists(preCfg.ConfigFile) {
		err := createDefaultConfigFile(preCfg.ConfigFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating "+
				"a default config file: %v\n", err)
		}
	}

	// Clean the config file path so that we can load it
	cfg.ConfigFile = util.CleanAndExpandPath(cfg.ConfigFile)

	// Load additional settings from the config file
	var configFileError error
	parser := flags.NewParser(cfg, flags.Default)
	err = flags.NewIniParser(parser).ParseFile(cfg.ConfigFile)
	if err != nil {
		var e *os.PathError
		if !errors.As(err, &e) {
			return nil, fmt.Errorf("parse config file: %v", err)
		}
		// There is something wrong with the config file path.
		// A config file may not exist. This will be logged as
		// a warning once the logger has been intialized.
		configFileError = err
	}

	// Parse command line options again to ensure they take
	// precedence. If unknown args are found, a warning will
	// be logged once the logger has been initialized.
	unknownArgs, err := parser.Parse()
	if err != nil {
		return nil, err
	}

	// Check for the show log level. This is used to list supported
	// subsystems and exit.
	if cfg.DebugLevel == "show" {
		fmt.Println("Supported subsystems", logger.SupportedSubsystems())
		os.Exit(0)
	}

	// Parse, validate, and set debug log level(s).
	if err := parseAndSetDebugLevels(cfg.DebugLevel); err != nil {
		return nil, err
	}

	// Clean and expand all file paths
	cfg.HomeDir = util.CleanAndExpandPath(cfg.HomeDir)
	cfg.DataDir = util.CleanAndExpandPath(cfg.DataDir)
	cfg.LogDir = util.CleanAndExpandPath(cfg.LogDir)
	cfg.ConfigFile = util.CleanAndExpandPath(cfg.ConfigFile)
	cfg.HTTPSCert = util.CleanAndExpandPath(cfg.HTTPSCert)
	cfg.HTTPSKey = util.CleanAndExpandPath(cfg.HTTPSKey)

	// Create the app directory if it doesn't already exist
	err = os.MkdirAll(cfg.HomeDir, 0700)
	if err != nil {
		return nil, fmt.Errorf("failed to create app dir: %v", err)
	}

	// Initialize log rotation. After the log rotation has
	// been initialized, the logger variables may be used.
	logger.InitLogRotator(filepath.Join(cfg.LogDir, defaultLogFilename))

	// Perform various validation and setup
	err = setupDBSettings(cfg)
	if err != nil {
		return nil, err
	}
	cfg.PluginSettings, err = parsePluginSettings(cfg.RawPluginSettings)
	if err != nil {
		return nil, err
	}
	if cfg.TestNet {
		cfg.ChainParams = chaincfg.TestNet3Params()
	}

	// Load the system cert pool
	cfg.SystemCerts, err = x509.SystemCertPool()
	if err != nil {
		log.Errorf("Failed to get the system cert pool: %v", err)
		cfg.SystemCerts = x509.NewCertPool()
	}

	// Log any config warnings
	if configFileError != nil {
		log.Warnf("Failed to parse config file: %v", configFileError)
	}
	if len(unknownArgs) != 0 {
		args := strings.Join(unknownArgs, ", ")
		log.Warnf("Unknown arguments found: %v", args)
	}

	return cfg, nil
}

// setupDBSettings performs any required validation and setup for the database
// config settings.
func setupDBSettings(cfg *config) error {
	// Validate the database host
	_, err := url.Parse(cfg.DBHost)
	if err != nil {
		return fmt.Errorf("invalid dbhost '%v': %v", cfg.DBHost, err)
	}

	// Pull the password from the env variable
	cfg.DBPass = os.Getenv(envDBPass)
	if cfg.DBPass == "" {
		return fmt.Errorf("dbpass not found; you must provide "+
			"the database password for the app user in the env "+
			"variable %v", envDBPass)
	}

	return nil
}

// createDefaultConfig copies sample config file to the given destination path.
func createDefaultConfigFile(destPath string) error {
	// Create the destination directory if it does not exist.
	err := os.MkdirAll(filepath.Dir(destPath), 0700)
	if err != nil {
		return err
	}

	// Create config file at the provided path.
	dest, err := os.OpenFile(destPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer dest.Close()

	_, err = dest.WriteString(sampleConfig)
	return err
}

// parseAndSetDebugLevels attempts to parse the specified debug level and set
// the levels accordingly. An appropriate error is returned if anything is
// invalid.
func parseAndSetDebugLevels(debugLevel string) error {
	// When the specified string doesn't have any
	// delimiters, treat it as the log level for all
	// subsystems.
	if !strings.Contains(debugLevel, ",") &&
		!strings.Contains(debugLevel, "=") {
		// Validate debug log level
		if !validLogLevel(debugLevel) {
			return fmt.Errorf("the specified debug level "+
				"[%v] is invalid", debugLevel)
		}

		// Change the logging level for all subsystems
		logger.SetLogLevels(debugLevel)

		return nil
	}

	// Split the specified string into subsystem/level pairs while
	// detecting issues and update the log levels accordingly.
	for _, logLevelPair := range strings.Split(debugLevel, ",") {
		if !strings.Contains(logLevelPair, "=") {
			str := "The specified debug level contains an invalid " +
				"subsystem/level pair [%v]"
			return fmt.Errorf(str, logLevelPair)
		}

		// Extract the specified subsystem and log level
		fields := strings.Split(logLevelPair, "=")
		subsysID, logLevel := fields[0], fields[1]

		// Validate subsystem
		subsystems := make(map[string]struct{})
		for _, v := range logger.SupportedSubsystems() {
			subsystems[v] = struct{}{}
		}
		if _, exists := subsystems[subsysID]; !exists {
			str := "The specified subsystem [%v] is invalid -- " +
				"supported subsytems %v"
			return fmt.Errorf(str, subsysID, logger.SupportedSubsystems())
		}

		// Validate log level
		if !validLogLevel(logLevel) {
			str := "The specified debug level [%v] is invalid"
			return fmt.Errorf(str, logLevel)
		}

		logger.SetLogLevel(subsysID, logLevel)
	}

	return nil
}

// validLogLevel returns whether the logLevel is a valid debug log level.
func validLogLevel(logLevel string) bool {
	_, ok := slog.LevelFromString(logLevel)
	return ok
}

// parsePluginSettings parses the raw plugin setting strings and converts
// them to app plugin settings.
func parsePluginSettings(rawSettings []string) (map[string][]app.Setting, error) {
	settings := make(map[string][]app.Setting, len(rawSettings))
	for _, v := range rawSettings {
		pluginID, s, err := parsePluginSetting(v)
		if err != nil {
			return nil, errors.Errorf("failed to parse plugin setting %v", v)
		}
		ps, ok := settings[pluginID]
		if !ok {
			ps = make([]app.Setting, 0, 16)
		}
		ps = append(ps, *s)
		settings[pluginID] = ps
	}
	return settings, nil
}

// parsePluginSetting parses a plugin setting. Plugin settings will be in
// following format. The value may be a single value or an array of values.
//
// pluginID,key,value
// pluginID,key,["value1","value2","value3"...]
//
// When multiple values are provided, the values must be formatted as a JSON
// encoded []string. Both of the following JSON formats are acceptable.
//
// pluginID,key,["value1","value2","value3"]
// pluginsetting="pluginID,key,[\"value1\",\"value2\",\"value3\"]"
func parsePluginSetting(setting string) (string, *app.Setting, error) {
	formatMsg := `expected plugin setting format is ` +
		`pluginID,key,value OR pluginID,key,["value1","value2","value3"]`

	// Parse the plugin setting
	var (
		parsed = strings.Split(setting, ",")

		// isMulti indicates whether the plugin setting contains
		// multiple values. If the setting only contains a single
		// value then isMulti will be false.
		isMulti = regexpPluginSettingMulti.MatchString(setting)
	)
	switch {
	case len(parsed) < 3:
		return "", nil, errors.Errorf("missing csv entry '%v'; %v",
			setting, formatMsg)
	case len(parsed) == 3:
		// This is expected; continue
	case len(parsed) > 3 && isMulti:
		// This is expected; continue
	default:
		return "", nil, errors.Errorf("invalid format '%v'; %v",
			setting, formatMsg)
	}

	var (
		pluginID     = parsed[0]
		settingName  = parsed[1]
		settingValue = parsed[2]
	)

	// Clean the strings. The setting value is allowed to be case
	// sensitive.
	pluginID = strings.ToLower(strings.TrimSpace(pluginID))
	settingName = strings.ToLower(strings.TrimSpace(settingName))
	settingValue = strings.TrimSpace(settingValue)

	// Handle multiple values
	if isMulti {
		// Parse values
		values := regexpPluginSettingMulti.FindString(setting)

		// Verify the values are formatted as valid JSON
		var s []string
		err := json.Unmarshal([]byte(values), &s)
		if err != nil {
			return "", nil, err
		}

		// Re-encode the JSON. This will remove any funny
		// formatting like whitespaces.
		b, err := json.Marshal(s)
		if err != nil {
			return "", nil, err
		}

		// Save the value
		settingValue = string(b)
	}

	return pluginID, &app.Setting{
		Name:  settingName,
		Value: settingValue,
	}, nil
}

var (
	// regexpPluginSettingMulti matches against the plugin setting value when it
	// contains multiple values.
	//
	// pluginID,key,["value1","value2"] matches ["value1","value2"]
	regexpPluginSettingMulti = regexp.MustCompile(`(\[.*\]$)`)
)
