// Copyright (c) 2013-2014 The btcsuite developers
// Copyright (c) 2015-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/go-socks/socks"
	"github.com/thi4go/politeia/util/version"
	flags "github.com/jessevdk/go-flags"
)

const (
	defaultConfigFilename = "politeiavoter.conf"
	defaultLogLevel       = "info"
	defaultLogDirname     = "logs"
	defaultVoteDirname    = "vote"
	defaultLogFilename    = "politeiavoter.log"
	defaultWalletHost     = "127.0.0.1"

	defaultWalletMainnetPort = "9111"
	defaultWalletTestnetPort = "19111"
)

var (
	defaultHomeDir        = dcrutil.AppDataDir("politeiavoter", false)
	defaultConfigFile     = filepath.Join(defaultHomeDir, defaultConfigFilename)
	defaultLogDir         = filepath.Join(defaultHomeDir, defaultLogDirname)
	defaultVoteDir        = filepath.Join(defaultHomeDir, defaultVoteDirname)
	dcrwalletHomeDir      = dcrutil.AppDataDir("dcrwallet", false)
	defaultWalletCertFile = filepath.Join(dcrwalletHomeDir, "rpc.cert")
)

// runServiceCommand is only set to a real function on Windows.  It is used
// to parse and execute service commands specified via the -s flag.
var runServiceCommand func(string) error

// config defines the configuration options for dcrd.
//
// See loadConfig for details on the configuration load process.
type config struct {
	HomeDir          string `short:"A" long:"appdata" description:"Path to application home directory"`
	ShowVersion      bool   `short:"V" long:"version" description:"Display version information and exit"`
	ConfigFile       string `short:"C" long:"configfile" description:"Path to configuration file"`
	LogDir           string `long:"logdir" description:"Directory to log output."`
	TestNet          bool   `long:"testnet" description:"Use the test network"`
	PoliteiaWWW      string `long:"politeiawww" description:"Politeia WWW host"`
	Profile          string `long:"profile" description:"Enable HTTP profiling on given port -- NOTE port must be between 1024 and 65536"`
	DebugLevel       string `short:"d" long:"debuglevel" description:"Logging level for all subsystems {trace, debug, info, warn, error, critical} -- You may also specify <subsystem>=<level>,<subsystem2>=<level>,... to set the log level for individual subsystems -- Use show to list available subsystems"`
	Version          string
	WalletHost       string `long:"wallethost" description:"Wallet host"`
	WalletCert       string `long:"walletgrpccert" description:"Wallet GRPC certificate"`
	WalletPassphrase string `long:"walletpassphrase" description:"Wallet decryption passphrase"`
	BypassProxyCheck bool   `long:"bypassproxycheck" description:"Don't use this unless you know what you're doing."`
	Proxy            string `long:"proxy" description:"Connect via SOCKS5 proxy (eg. 127.0.0.1:9050)"`
	ProxyUser        string `long:"proxyuser" description:"Username for proxy server"`
	ProxyPass        string `long:"proxypass" default-mask:"-" description:"Password for proxy server"`
	VoteDuration     string `long:"voteduration" description:"Duration to cast all votes in hours and minutes e.g. 5h10m (default 0s means autodetect duration)"`
	Trickle          bool   `long:"trickle" description:"Enable vote trickling, requires --proxy."`
	SkipVerify       bool   `long:"skipverify" description:"Skip verifying the server's certifcate chain and host name."`

	voteDir      string
	dial         func(string, string) (net.Conn, error)
	voteDuration time.Duration // Parsed VoteDuration
	blocksPerDay uint64
}

// serviceOptions defines the configuration options for the daemon as a service
// on Windows.
type serviceOptions struct {
	ServiceCommand string `short:"s" long:"service" description:"Service command {install, remove, start, stop}"`
}

// cleanAndExpandPath expands environment variables and leading ~ in the
// passed path, cleans the result, and returns it.
func cleanAndExpandPath(path string) string {
	// Expand initial ~ to OS specific home directory.
	if strings.HasPrefix(path, "~") {
		homeDir := filepath.Dir(defaultHomeDir)
		path = strings.Replace(path, "~", homeDir, 1)
	}

	// NOTE: The os.ExpandEnv doesn't work with Windows-style %VARIABLE%,
	// but the variables can still be expanded via POSIX-style $VARIABLE.
	return filepath.Clean(os.ExpandEnv(path))
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

// supportedSubsystems returns a sorted slice of the supported subsystems for
// logging purposes.
func supportedSubsystems() []string {
	// Convert the subsystemLoggers map keys to a slice.
	subsystems := make([]string, 0, len(subsystemLoggers))
	for subsysID := range subsystemLoggers {
		subsystems = append(subsystems, subsysID)
	}

	// Sort the subsytems for stable display.
	sort.Strings(subsystems)
	return subsystems
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
		setLogLevels(debugLevel)

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
		if _, exists := subsystemLoggers[subsysID]; !exists {
			str := "The specified subsystem [%v] is invalid -- " +
				"supported subsytems %v"
			return fmt.Errorf(str, subsysID, supportedSubsystems())
		}

		// Validate log level.
		if !validLogLevel(logLevel) {
			str := "The specified debug level [%v] is invalid"
			return fmt.Errorf(str, logLevel)
		}

		setLogLevel(subsysID, logLevel)
	}

	return nil
}

// newConfigParser returns a new command line flags parser.
func newConfigParser(cfg *config, so *serviceOptions, options flags.Options) *flags.Parser {
	parser := flags.NewParser(cfg, options)
	if runtime.GOOS == "windows" {
		parser.AddGroup("Service Options", "Service Options", so)
	}
	return parser
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
// The above results in daemon functioning properly without any config settings
// while still allowing the user to override settings with config files and
// command line options.  Command line options always take precedence.
func loadConfig() (*config, []string, error) {
	// Default config.
	cfg := config{
		HomeDir:    defaultHomeDir,
		ConfigFile: defaultConfigFile,
		DebugLevel: defaultLogLevel,
		LogDir:     defaultLogDir,
		voteDir:    defaultVoteDir,
		Version:    version.String(),
	}

	// Service options which are only added on Windows.
	serviceOpts := serviceOptions{}

	// Pre-parse the command line options to see if an alternative config
	// file or the version flag was specified.  Any errors aside from the
	// help message error can be ignored here since they will be caught by
	// the final parse below.
	preCfg := cfg
	preParser := newConfigParser(&preCfg, &serviceOpts, flags.HelpFlag)
	_, err := preParser.Parse()
	if err != nil {
		if e, ok := err.(*flags.Error); ok && e.Type != flags.ErrHelp {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		} else if ok && e.Type == flags.ErrHelp {
			fmt.Fprintln(os.Stdout, err)
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

	// Update the home directory for stakepoold if specified. Since the
	// home directory is updated, other variables need to be updated to
	// reflect the new changes.
	if preCfg.HomeDir != "" {
		cfg.HomeDir, _ = filepath.Abs(preCfg.HomeDir)

		if preCfg.ConfigFile == defaultConfigFile {
			cfg.ConfigFile = filepath.Join(cfg.HomeDir, defaultConfigFilename)
		} else {
			cfg.ConfigFile = preCfg.ConfigFile
		}
		if preCfg.LogDir == defaultLogDir {
			cfg.LogDir = filepath.Join(cfg.HomeDir, defaultLogDirname)
		} else {
			cfg.LogDir = preCfg.LogDir
		}
		if preCfg.voteDir == defaultVoteDir {
			cfg.voteDir = filepath.Join(cfg.HomeDir, defaultVoteDirname)
		} else {
			cfg.voteDir = preCfg.voteDir
		}
	}

	// Load additional config from file.
	var configFileError error
	parser := newConfigParser(&cfg, &serviceOpts, flags.Default)
	err = flags.NewIniParser(parser).ParseFile(cfg.ConfigFile)
	if err != nil {
		if _, ok := err.(*os.PathError); !ok {
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
		if e, ok := err.(*flags.Error); !ok || e.Type != flags.ErrHelp {
			fmt.Fprintln(os.Stderr, usageMessage)
		}
		return nil, nil, err
	}

	// Create the home directory if it doesn't already exist.
	funcName := "loadConfig"
	err = os.MkdirAll(cfg.HomeDir, 0700)
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

		str := "%s: Failed to create home directory: %v"
		err := fmt.Errorf(str, funcName, err)
		fmt.Fprintln(os.Stderr, err)
		return nil, nil, err
	}

	// Create vote directory if it doesn't already exist.
	err = os.MkdirAll(cfg.voteDir, 0700)
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

		str := "%s: Failed to create vote directory: %v"
		err := fmt.Errorf(str, funcName, err)
		fmt.Fprintln(os.Stderr, err)
		return nil, nil, err
	}

	// Count number of network flags passed; assign active network params
	// while we're at it
	activeNetParams = &mainNetParams
	if cfg.TestNet {
		activeNetParams = &testNet3Params
	}

	// Calculate blocks per day
	cfg.blocksPerDay = uint64(24 * time.Hour /
		activeNetParams.TargetTimePerBlock)

	// Determine default connections
	if cfg.PoliteiaWWW == "" {
		if activeNetParams.Name == "mainnet" {
			cfg.PoliteiaWWW = "https://proposals.decred.org/api"
		} else {
			cfg.PoliteiaWWW = "https://test-proposals.decred.org/api"
		}
	}

	if cfg.WalletHost == "" {
		if activeNetParams.Name == "mainnet" {
			cfg.WalletHost = defaultWalletHost + ":" +
				defaultWalletMainnetPort
		} else {
			cfg.WalletHost = defaultWalletHost + ":" +
				defaultWalletTestnetPort
		}
	}
	// Append the network type to the log directory so it is "namespaced"
	// per network in the same fashion as the data directory.
	cfg.LogDir = cleanAndExpandPath(cfg.LogDir)
	cfg.LogDir = filepath.Join(cfg.LogDir, netName(activeNetParams))

	// Special show command to list supported subsystems and exit.
	if cfg.DebugLevel == "show" {
		fmt.Println("Supported subsystems", supportedSubsystems())
		os.Exit(0)
	}

	// Initialize log rotation.  After log rotation has been initialized,
	// the logger variables may be used.
	initLogRotator(filepath.Join(cfg.LogDir, defaultLogFilename))

	// Parse, validate, and set debug log level(s).
	if err := parseAndSetDebugLevels(cfg.DebugLevel); err != nil {
		err := fmt.Errorf("%s: %v", funcName, err.Error())
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, usageMessage)
		return nil, nil, err
	}

	// Validate profile port number
	if cfg.Profile != "" {
		profilePort, err := strconv.Atoi(cfg.Profile)
		if err != nil || profilePort < 1024 || profilePort > 65535 {
			str := "%s: The profile port must be between 1024 and 65535"
			err := fmt.Errorf(str, funcName)
			fmt.Fprintln(os.Stderr, err)
			fmt.Fprintln(os.Stderr, usageMessage)
			return nil, nil, err
		}
	}

	// Wallet cert
	if cfg.WalletCert == "" {
		cfg.WalletCert = defaultWalletCertFile
	}
	cfg.WalletCert = cleanAndExpandPath(cfg.WalletCert)

	// Warn about missing config file only after all other configuration is
	// done.  This prevents the warning on help messages and invalid
	// options.  Note this should go directly before the return.
	if configFileError != nil {
		log.Warnf("%v", configFileError)
	}

	// Socks proxy
	cfg.dial = net.Dial
	if cfg.Proxy != "" {
		_, _, err := net.SplitHostPort(cfg.Proxy)
		if err != nil {
			str := "%s: proxy address '%s' is invalid: %v"
			err := fmt.Errorf(str, funcName, cfg.Proxy, err)
			fmt.Fprintln(os.Stderr, err)
			fmt.Fprintln(os.Stderr, usageMessage)
			return nil, nil, fmt.Errorf("invalid --proxy %v", err)
		}
		proxy := &socks.Proxy{
			Addr:         cfg.Proxy,
			Username:     cfg.ProxyUser,
			Password:     cfg.ProxyPass,
			TorIsolation: true,
		}
		cfg.dial = proxy.Dial
	}

	// VoteDuration can only be set with trickle enable.
	if cfg.VoteDuration != "" && !cfg.Trickle {
		return nil, nil, fmt.Errorf("must use --trickle when " +
			"--voteduration is set")
	}
	// Duration of the vote.
	if cfg.VoteDuration != "" {
		// Verify we can parse the duration
		cfg.voteDuration, err = time.ParseDuration(cfg.VoteDuration)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid --voteduration "+
				"%v", err)
		}
	}

	if !cfg.BypassProxyCheck {
		if cfg.Trickle && cfg.Proxy == "" {
			return nil, nil, fmt.Errorf("cannot use --voteduration " +
				"without --trickle")
		}
	}

	return &cfg, remainingArgs, nil
}
