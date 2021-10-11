// Copyright (c) 2013-2014 The btcsuite developers
// Copyright (c) 2015-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package config

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/decred/dcrd/dcrutil/v3"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiawww/logger"
	"github.com/decred/politeia/util"
	"github.com/decred/politeia/util/version"
	"github.com/jessevdk/go-flags"
)

const (
	appName = "politeiawww"

	// General application settings
	defaultDataDirname    = "data"
	defaultLogLevel       = "info"
	defaultLogDirname     = "logs"
	defaultConfigFilename = "politeiawww.conf"
	defaultLogFilename    = "politeiawww.log"

	// HTTP server settings
	defaultMainnetPort       = "4443"
	defaultTestnetPort       = "4443"
	defaultHTTPSCertFilename = "https.cert"
	defaultHTTPSKeyFilename  = "https.key"
	defaultCookieKeyFilename = "cookie.key"

	defaultReadTimeout        int64 = 5               // In seconds
	defaultWriteTimeout       int64 = 60              // In seconds
	defaultReqBodySizeLimit   int64 = 3 * 1024 * 1024 // 3 MiB
	defaultWebsocketReadLimit int64 = 4 * 1024 * 1024 // 4 KiB

	// politeiad RPC settings
	defaultRPCHost          = "localhost"
	defaultRPCMainnetPort   = "49374"
	defaultRPCTestnetPort   = "59374"
	defaultRPCCertFilename  = "rpc.cert"
	defaultIdentityFilename = "identity.json"
	allowInteractive        = "i-know-this-is-a-bad-idea"

	// Database settings
	LevelDB     = "leveldb"
	CockroachDB = "cockroachdb"
	MySQL       = "mysql"

	defaultMySQLDBHost     = "localhost:3306"
	defaultCockroachDBHost = "localhost:26257"

	// SMTP settings
	defaultMailAddress = "Politeia <noreply@example.org>"

	// Environmental variable config settings
	envDBPass = "DBPASS"
)

var (
	// General application settings
	defaultHomeDir    = dcrutil.AppDataDir(appName, false)
	defaultConfigFile = filepath.Join(defaultHomeDir, defaultConfigFilename)
	defaultDataDir    = filepath.Join(defaultHomeDir, defaultDataDirname)
	defaultLogDir     = filepath.Join(defaultHomeDir, defaultLogDirname)
)

// Config defines the configuration options for politeiawww.
type Config struct {
	// General application settings
	ShowVersion bool   `short:"V" long:"version" description:"Display version information and exit"`
	HomeDir     string `short:"A" long:"appdata" description:"Path to application home directory"`
	ConfigFile  string `short:"C" long:"configfile" description:"Path to configuration file"`
	DataDir     string `short:"b" long:"datadir" description:"Directory to store data"`
	LogDir      string `long:"logdir" description:"Directory to log output."`
	TestNet     bool   `long:"testnet" description:"Use the test network"`
	DebugLevel  string `short:"d" long:"debuglevel" description:"Logging level for all subsystems {trace, debug, info, warn, error, critical} -- You may also specify <subsystem>=<level>,<subsystem2>=<level>,... to set the log level for individual subsystems -- Use show to list available subsystems"`

	// HTTP server settings
	Listeners          []string `long:"listen" description:"Add an interface/port to listen for connections (default all interfaces port: 4443)"`
	HTTPSCert          string   `long:"httpscert" description:"File containing the https certificate file"`
	HTTPSKey           string   `long:"httpskey" description:"File containing the https certificate key"`
	CookieKeyFile      string   `long:"cookiekey" description:"File containing the secret cookies key"`
	ReadTimeout        int64    `long:"readtimeout" description:"Maximum duration in seconds that is spent reading the request headers and body"`
	WriteTimeout       int64    `long:"writetimeout" description:"Maximum duration in seconds that a request connection is kept open"`
	ReqBodySizeLimit   int64    `long:"reqbodysizelimit" description:"Maximum number of bytes allowed in a request body submitted by a client"`
	WebsocketReadLimit int64    `long:"websocketreadlimit" description:"Maximum number of bytes allowed for a message read from a websocket client"`

	// politeiad RPC settings
	RPCHost         string `long:"rpchost" description:"politeiad host <host>:<port>"`
	RPCCert         string `long:"rpccert" description:"File containing the politeiad https certificate file"`
	RPCIdentityFile string `long:"rpcidentityfile" description:"Path to file containing the politeiad identity"`
	RPCUser         string `long:"rpcuser" description:"RPC username for privileged politeaid commands"`
	RPCPass         string `long:"rpcpass" description:"RPC password for privileged politeiad commands"`
	FetchIdentity   bool   `long:"fetchidentity" description:"Fetch the identity from politeiad"`
	Interactive     string `long:"interactive" description:"Set to i-know-this-is-a-bad-idea to turn off interactive mode during --fetchidentity"`

	// User database settings
	UserDB string `long:"userdb" description:"Database choice for the user database"`
	DBHost string `long:"dbhost" description:"Database ip:port"`
	DBPass string // Provided in env variable "DBPASS"

	// SMTP settings
	MailHost       string `long:"mailhost" description:"Email server address <host>:<port>"`
	MailCert       string `long:"mailcert" description:"Email server certificate file"`
	MailSkipVerify bool   `long:"mailskipverify" description:"Skip email server TLS verification"`
	MailUser       string `long:"mailuser" description:"Email server username"`
	MailPass       string `long:"mailpass" description:"Email server password"`
	MailAddress    string `long:"mailaddress" description:"Email address for outgoing email in the format: name <address>"`

	// Embedded legacy config. This will be deleted soon.
	LegacyConfig

	Version     string
	ActiveNet   *ChainParams             // Active DCR network
	Identity    *identity.PublicIdentity // politeiad identity
	SystemCerts *x509.CertPool
}

// Load initializes and parses the config using a config file and command line
// options.
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
func Load() (*Config, []string, error) {
	// Setup the default config. Most of settings that contain file
	// paths are not set to default values and handled later on, once
	// the CLI args and config file have been fully parsed so that we
	// don't need to worry about updating the default paths with any
	// changes to the home dir.
	cfg := &Config{
		// General application settings
		ShowVersion: false,
		HomeDir:     defaultHomeDir,
		ConfigFile:  defaultConfigFile,
		DataDir:     defaultDataDir,
		LogDir:      defaultLogDir,
		TestNet:     false,
		DebugLevel:  defaultLogLevel,

		// HTTP server settings
		Listeners:          []string{},
		HTTPSCert:          "",
		HTTPSKey:           "",
		CookieKeyFile:      "",
		ReadTimeout:        defaultReadTimeout,
		WriteTimeout:       defaultWriteTimeout,
		ReqBodySizeLimit:   defaultReqBodySizeLimit,
		WebsocketReadLimit: defaultWebsocketReadLimit,

		// User database settings
		UserDB: LevelDB,

		// SMTP settings
		MailAddress: defaultMailAddress,

		// Legacy settings. These are deprecated and will be removed soon.
		LegacyConfig: LegacyConfig{
			Mode:                     PiWWWMode,
			PaywallAmount:            defaultPaywallAmount,
			MinConfirmationsRequired: defaultPaywallMinConfirmations,
			VoteDurationMin:          defaultVoteDurationMin,
			VoteDurationMax:          defaultVoteDurationMax,
			MailRateLimit:            defaultMailRateLimit,
		},
	}

	// Service options which are only added on Windows.
	serviceOpts := serviceOptions{}

	// Pre-parse the command line options to see if an alternative config
	// file or the version flag was specified.  Any errors aside from the
	// help message error can be ignored here since they will be caught by
	// the final parse below.
	preCfg := cfg
	preParser := newConfigParser(preCfg, &serviceOpts, flags.HelpFlag)
	_, err := preParser.Parse()
	if err != nil {
		var e *flags.Error
		if errors.As(err, &e) && e.Type == flags.ErrHelp {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(0)
		}
	}

	// Show the version and exit if the version flag was specified.
	appName := filepath.Base(os.Args[0])
	appName = strings.TrimSuffix(appName, filepath.Ext(appName))
	usageMessage := fmt.Sprintf("Use %s -h to show usage", appName)
	if preCfg.ShowVersion {
		fmt.Printf("%s version %s (Go version %s %s/%s)\n", appName,
			version.String(), runtime.Version(), runtime.GOOS,
			runtime.GOARCH)
		os.Exit(0)
	}

	// Perform service command and exit if specified.  Invalid service
	// commands show an appropriate error.  Only runs on Windows since
	// the runServiceCommand function will be nil when not on Windows.
	if serviceOpts.ServiceCommand != "" && runServiceCommand != nil {
		err := runServiceCommand(serviceOpts.ServiceCommand)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(0)
	}

	// Update the home directory if specified. Since the home directory is
	// updated, other variables need to be updated to reflect the new changes.
	if preCfg.HomeDir != "" {
		cfg.HomeDir, _ = filepath.Abs(preCfg.HomeDir)

		if preCfg.ConfigFile == defaultConfigFile {
			cfg.ConfigFile = filepath.Join(cfg.HomeDir, defaultConfigFilename)
		} else {
			cfg.ConfigFile = preCfg.ConfigFile
		}
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
	}

	// Clean and exand the config file path.
	cfg.ConfigFile = util.CleanAndExpandPath(cfg.ConfigFile)

	// Load additional config from file.
	var configFileError error
	parser := newConfigParser(cfg, &serviceOpts, flags.Default)
	err = flags.NewIniParser(parser).ParseFile(cfg.ConfigFile)
	if err != nil {
		var e *os.PathError
		if !errors.As(err, &e) {
			fmt.Fprintf(os.Stderr, "Error parsing config "+
				"file: %v\n", err)
			fmt.Fprintln(os.Stderr, usageMessage)
			return nil, nil, err
		}
		configFileError = err
	}

	// Parse command line options again to ensure they take precedence.
	remainingArgs, err := parser.Parse()
	if err != nil {
		var e *flags.Error
		if !errors.As(err, &e) || e.Type != flags.ErrHelp {
			fmt.Fprintln(os.Stderr, usageMessage)
		}
		return nil, nil, err
	}

	// Special show command to list supported subsystems and exit.
	if cfg.DebugLevel == "show" {
		fmt.Println("Supported subsystems", logger.SupportedSubsystems())
		os.Exit(0)
	}

	// Clean and expand all file paths
	cfg.HomeDir = util.CleanAndExpandPath(cfg.HomeDir)
	cfg.ConfigFile = util.CleanAndExpandPath(cfg.ConfigFile)
	cfg.DataDir = util.CleanAndExpandPath(cfg.DataDir)
	cfg.LogDir = util.CleanAndExpandPath(cfg.LogDir)

	// Create the home directory if it doesn't already exist.
	funcName := "loadConfig"
	err = os.MkdirAll(cfg.HomeDir, 0700)
	if err != nil {
		// Show a nicer error message if it's because a symlink
		// is linked to a directory that does not exist (probably
		// because it's not mounted).
		var e *os.PathError
		if errors.As(err, &e) && os.IsExist(err) {
			if link, lerr := os.Readlink(e.Path); lerr == nil {
				str := "is symlink %s -> %s mounted?"
				err = fmt.Errorf(str, e.Path, link)
			}
		}

		str := "%s: Failed to create home directory: %v"
		err := fmt.Errorf(str, funcName, err)
		fmt.Fprintln(os.Stderr, err)
		return nil, nil, err
	}

	// Setup the active network
	cfg.ActiveNet = &mainNetParams
	if cfg.TestNet {
		cfg.ActiveNet = &testNet3Params
	}

	// Append the network type to the data and log directories
	// so that they are "namespaced" per network.
	cfg.DataDir = filepath.Join(cfg.DataDir, netName(cfg.ActiveNet))
	cfg.LogDir = filepath.Join(cfg.LogDir, netName(cfg.ActiveNet))

	// Parse, validate, and set debug log level(s).
	if err := parseAndSetDebugLevels(cfg.DebugLevel); err != nil {
		err := fmt.Errorf("%s: %v", funcName, err.Error())
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, usageMessage)
		return nil, nil, err
	}

	// Initialize log rotation. After the log rotation has
	// been initialized, the logger variables may be used.
	logger.InitLogRotator(filepath.Join(cfg.LogDir, defaultLogFilename))

	// Load the system cert pool
	cfg.SystemCerts, err = x509.SystemCertPool()
	if err != nil {
		return nil, nil, err
	}

	// Setup the various config settings
	err = setupHTTPServerSettings(cfg)
	if err != nil {
		return nil, nil, err
	}
	err = setupRPCSettings(cfg)
	if err != nil {
		return nil, nil, err
	}
	err = setupUserDBSettings(cfg)
	if err != nil {
		return nil, nil, err
	}
	err = setupMailSettings(cfg)
	if err != nil {
		return nil, nil, err
	}
	err = setupLegacyConfig(cfg)
	if err != nil {
		return nil, nil, err
	}

	// Warn about missing config file only after all other
	// configuration is done. This prevents the warning on
	// help messages and invalid options. Note this should
	// go directly before the return.
	if configFileError != nil {
		log.Warnf("%v", configFileError)
	}

	return cfg, remainingArgs, nil
}

// setupHTTPServerSettings sets up the politeiawww http server config settings.
func setupHTTPServerSettings(cfg *Config) error {
	// Setup default values if none were provided. Only the file path
	// defaults need to be checked. All other defaults should be set
	// on the original config initialization.
	if cfg.HTTPSCert == "" {
		cfg.HTTPSCert = filepath.Join(cfg.HomeDir, defaultHTTPSCertFilename)
	}
	if cfg.HTTPSKey == "" {
		cfg.HTTPSKey = filepath.Join(cfg.HomeDir, defaultHTTPSKeyFilename)
	}
	if cfg.CookieKeyFile == "" {
		cfg.CookieKeyFile = filepath.Join(cfg.HomeDir, defaultCookieKeyFilename)
	}

	// Clean file paths
	cfg.HTTPSCert = util.CleanAndExpandPath(cfg.HTTPSCert)
	cfg.HTTPSKey = util.CleanAndExpandPath(cfg.HTTPSKey)
	cfg.CookieKeyFile = util.CleanAndExpandPath(cfg.CookieKeyFile)

	// Add the default listener if none were specified. The
	// default listener is all addresses on the listen port
	// for the network we are to connect to.
	port := defaultMainnetPort
	if cfg.TestNet {
		port = defaultTestnetPort
	}
	if len(cfg.Listeners) == 0 {
		cfg.Listeners = []string{
			net.JoinHostPort("", port),
		}
	}

	// Add default port to all listener addresses if needed
	// and remove duplicate addresses.
	cfg.Listeners = normalizeAddresses(cfg.Listeners, port)

	return nil
}

// setupRPCSettings sets up the politeiad RPC config settings.
func setupRPCSettings(cfg *Config) error {
	// Setup default values if none were provided
	if cfg.RPCCert == "" {
		cfg.RPCCert = filepath.Join(cfg.HomeDir, defaultRPCCertFilename)
	}
	if cfg.RPCIdentityFile == "" {
		cfg.RPCIdentityFile = filepath.Join(cfg.HomeDir, defaultIdentityFilename)
	}

	// Clean file paths
	cfg.RPCCert = util.CleanAndExpandPath(cfg.RPCCert)
	cfg.RPCIdentityFile = util.CleanAndExpandPath(cfg.RPCIdentityFile)

	// Setup the RPC host
	if cfg.RPCHost == "" {
		cfg.RPCHost = defaultRPCHost
	}
	port := defaultRPCMainnetPort
	if cfg.TestNet {
		port = defaultRPCTestnetPort
	}
	cfg.RPCHost = util.NormalizeAddress(cfg.RPCHost, port)
	u, err := url.Parse("https://" + cfg.RPCHost)
	if err != nil {
		return fmt.Errorf("parse politeiad RPC host: %v", err)
	}
	cfg.RPCHost = u.String()

	// Verify remaining RPC settings
	if cfg.RPCUser == "" {
		return fmt.Errorf("politeiad rpc user " +
			"must be provided with --rpcuser")
	}
	if cfg.RPCPass == "" {
		return fmt.Errorf("politeiad rpc pass " +
			"must be provided with --rpcpass")
	}
	if cfg.Interactive != "" && cfg.Interactive != allowInteractive {
		return fmt.Errorf("--interactive flag used incorrectly")
	}

	// Load the identity politeaid identity from disk
	if cfg.FetchIdentity {
		// Don't try to load the identity from the existing
		// file if the caller is trying to fetch a new one.
		return nil
	}
	if !util.FileExists(cfg.RPCIdentityFile) {
		return fmt.Errorf("identity file not found; you must load the " +
			"identity from politeiad first using the --fetchidentity flag")
	}
	cfg.Identity, err = identity.LoadPublicIdentity(cfg.RPCIdentityFile)
	if err != nil {
		return err
	}

	log.Infof("Identity loaded from: %v", cfg.RPCIdentityFile)

	return nil
}

// setupUserDBSettings sets up the user database config settings.
func setupUserDBSettings(cfg *Config) error {
	// Verify database selection
	switch cfg.UserDB {
	case LevelDB, CockroachDB, MySQL:
		// These are allowed
	default:
		return fmt.Errorf("invalid db selection '%v'",
			cfg.UserDB)
	}

	// Verify individual database requirements
	switch cfg.UserDB {
	case LevelDB:
		// LevelDB should not have a host
		if cfg.DBHost != "" {
			return fmt.Errorf("dbhost should not be set when using leveldb")
		}

	case CockroachDB:
		// The CockroachDB option is deprecated. All CockroachDB
		// validation is performed in the legacy config setup.

	case MySQL:
		// Verify database host
		if cfg.DBHost == "" {
			cfg.DBHost = defaultMySQLDBHost
		}
		_, err := url.Parse(cfg.DBHost)
		if err != nil {
			return fmt.Errorf("invalid dbhost '%v': %v",
				cfg.DBHost, err)
		}

		// Pull password from env variable
		cfg.DBPass = os.Getenv(envDBPass)
		if cfg.DBPass == "" {
			return fmt.Errorf("dbpass not found; you must provide "+
				"the database password for the politeiawww user in "+
				"the env variable %v", envDBPass)
		}
	}

	return nil
}

// setupMailSettings sets up the SMTP mail server config settings.
func setupMailSettings(cfg *Config) error {
	// Clean file paths
	cfg.MailCert = util.CleanAndExpandPath(cfg.MailCert)

	// Verify the host
	u, err := url.Parse(cfg.MailHost)
	if err != nil {
		return fmt.Errorf("unable to parse mail host: %v", err)
	}
	cfg.MailHost = u.String()

	// Verify the certificate
	if cfg.MailCert != "" {
		if cfg.MailSkipVerify {
			return fmt.Errorf("cannot set mailskipverify " +
				"and provide a mailcert at the same time")
		}
		if !util.FileExists(cfg.MailCert) {
			return fmt.Errorf("mail cert file '%v' not found",
				cfg.MailCert)
		}
		b, err := ioutil.ReadFile(cfg.MailCert)
		if err != nil {
			return fmt.Errorf("read mail cert: %v", err)
		}
		block, _ := pem.Decode(b)
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse mail cert: %v", err)
		}
		cfg.SystemCerts.AddCert(cert)
	}

	// Verify the provided email address
	a, err := mail.ParseAddress(cfg.MailAddress)
	if err != nil {
		return fmt.Errorf("cannot parse mail address '%v': %v",
			cfg.MailAddress, err)
	}
	cfg.MailAddress = a.String()

	return nil
}

// runServiceCommand is only set to a real function on Windows.  It is used
// to parse and execute service commands specified via the -s flag.
var runServiceCommand func(string) error

// serviceOptions defines the configuration options for the rpc as a service
// on Windows.
type serviceOptions struct {
	ServiceCommand string `short:"s" long:"service" description:"Service command {install, remove, start, stop}"`
}

// newConfigParser returns a new command line flags parser.
func newConfigParser(cfg *Config, so *serviceOptions, options flags.Options) *flags.Parser {
	parser := flags.NewParser(cfg, options)
	if runtime.GOOS == "windows" {
		parser.AddGroup("Service Options", "Service Options", so)
	}
	return parser
}

// validLogLevel returns whether or not logLevel is a valid debug log level.
func validLogLevel(logLevel string) bool {
	switch logLevel {
	case "trace":
		fallthrough
	case "debug":
		fallthrough
	case "info":
		fallthrough
	case "warn":
		fallthrough
	case "error":
		fallthrough
	case "critical":
		return true
	}
	return false
}

// parseAndSetDebugLevels attempts to parse the specified debug level and set
// the levels accordingly.  An appropriate error is returned if anything is
// invalid.
func parseAndSetDebugLevels(debugLevel string) error {
	// When the specified string doesn't have any delimters, treat it as
	// the log level for all subsystems.
	if !strings.Contains(debugLevel, ",") && !strings.Contains(debugLevel, "=") {
		// Validate debug log level.
		if !validLogLevel(debugLevel) {
			str := "The specified debug level [%v] is invalid"
			return fmt.Errorf(str, debugLevel)
		}

		// Change the logging level for all subsystems.
		logger.SetLogLevels(debugLevel)

		return nil
	}

	// Split the specified string into subsystem/level pairs while detecting
	// issues and update the log levels accordingly.
	for _, logLevelPair := range strings.Split(debugLevel, ",") {
		if !strings.Contains(logLevelPair, "=") {
			str := "The specified debug level contains an invalid " +
				"subsystem/level pair [%v]"
			return fmt.Errorf(str, logLevelPair)
		}

		// Extract the specified subsystem and log level.
		fields := strings.Split(logLevelPair, "=")
		subsysID, logLevel := fields[0], fields[1]

		// Validate subsystem.
		subsystems := make(map[string]struct{})
		for _, v := range logger.SupportedSubsystems() {
			subsystems[v] = struct{}{}
		}
		if _, exists := subsystems[subsysID]; !exists {
			str := "The specified subsystem [%v] is invalid -- " +
				"supported subsytems %v"
			return fmt.Errorf(str, subsysID, logger.SupportedSubsystems())
		}

		// Validate log level.
		if !validLogLevel(logLevel) {
			str := "The specified debug level [%v] is invalid"
			return fmt.Errorf(str, logLevel)
		}

		logger.SetLogLevel(subsysID, logLevel)
	}

	return nil
}

// normalizeAddresses returns a new slice with all the passed peer addresses
// normalized with the given default port, and all duplicates removed.
func normalizeAddresses(addrs []string, defaultPort string) []string {
	for i, addr := range addrs {
		addrs[i] = util.NormalizeAddress(addr, defaultPort)
	}

	return removeDuplicateAddresses(addrs)
}

// removeDuplicateAddresses returns a new slice with all duplicate entries in
// addrs removed.
func removeDuplicateAddresses(addrs []string) []string {
	result := make([]string, 0, len(addrs))
	seen := map[string]struct{}{}
	for _, val := range addrs {
		if _, ok := seen[val]; !ok {
			result = append(result, val)
			seen[val] = struct{}{}
		}
	}
	return result
}
