// Copyright (c) 2013-2014 The btcsuite developers
// Copyright (c) 2015-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/mail"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/decred/dcrd/hdkeychain/v3"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/util/version"

	v1 "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiawww/sharedconfig"
	"github.com/decred/politeia/util"
	flags "github.com/jessevdk/go-flags"
)

const (
	defaultLogLevel         = "info"
	defaultLogDirname       = "logs"
	defaultLogFilename      = "politeiawww.log"
	adminLogFilename        = "admin.log"
	defaultIdentityFilename = "identity.json"

	defaultMainnetPort = "4443"
	defaultTestnetPort = "4443"

	allowInteractive = "i-know-this-is-a-bad-idea"

	defaultPaywallMinConfirmations = uint64(2)
	defaultPaywallAmount           = uint64(0)

	defaultVoteDurationMin = uint32(2016)
	defaultVoteDurationMax = uint32(4032)

	defaultMailAddress    = "Politeia <noreply@example.org>"
	defaultCMSMailAddress = "Contractor Management System <noreply@example.org>"

	defaultDcrdataMainnet = "dcrdata.decred.org:443"
	defaultDcrdataTestnet = "testnet.decred.org:443"

	// dust value can be found increasing the amount value until we get false
	// from IsDustAmount function. Amounts can not be lower than dust
	// func IsDustAmount(amount int64, relayFeePerKb int64) bool {
	//     totalSize := 8 + 2 + 1 + 25 + 165
	// 	   return int64(amount)*1000/(3*int64(totalSize)) < int64(relayFeePerKb)
	// }
	dust = 60300

	// Currently available modes to run politeia, by default piwww, is used.
	politeiaWWWMode = "piwww"
	cmsWWWMode      = "cmswww"

	defaultWWWMode = politeiaWWWMode

	// User database options
	userDBLevel     = "leveldb"
	userDBCockroach = "cockroachdb"

	defaultUserDB = userDBLevel
)

var (
	defaultHTTPSKeyFile  = filepath.Join(sharedconfig.DefaultHomeDir, "https.key")
	defaultHTTPSCertFile = filepath.Join(sharedconfig.DefaultHomeDir, "https.cert")
	defaultRPCCertFile   = filepath.Join(sharedconfig.DefaultHomeDir, "rpc.cert")
	defaultCookieKeyFile = filepath.Join(sharedconfig.DefaultHomeDir, "cookie.key")
	defaultLogDir        = filepath.Join(sharedconfig.DefaultHomeDir, defaultLogDirname)
)

// runServiceCommand is only set to a real function on Windows.  It is used
// to parse and execute service commands specified via the -s flag.
var runServiceCommand func(string) error

// config defines the configuration options for politeiawww.
//
// See loadConfig for details on the configuration load process.
type config struct {
	HomeDir                  string   `short:"A" long:"appdata" description:"Path to application home directory"`
	ShowVersion              bool     `short:"V" long:"version" description:"Display version information and exit"`
	ConfigFile               string   `short:"C" long:"configfile" description:"Path to configuration file"`
	DataDir                  string   `short:"b" long:"datadir" description:"Directory to store data"`
	LogDir                   string   `long:"logdir" description:"Directory to log output."`
	TestNet                  bool     `long:"testnet" description:"Use the test network"`
	SimNet                   bool     `long:"simnet" description:"Use the simulation test network"`
	Profile                  string   `long:"profile" description:"Enable HTTP profiling on given port -- NOTE port must be between 1024 and 65536"`
	CookieKeyFile            string   `long:"cookiekey" description:"File containing the secret cookies key"`
	CPUProfile               string   `long:"cpuprofile" description:"Write CPU profile to the specified file"`
	MemProfile               string   `long:"memprofile" description:"Write mem profile to the specified file"`
	DebugLevel               string   `short:"d" long:"debuglevel" description:"Logging level for all subsystems {trace, debug, info, warn, error, critical} -- You may also specify <subsystem>=<level>,<subsystem2>=<level>,... to set the log level for individual subsystems -- Use show to list available subsystems"`
	Listeners                []string `long:"listen" description:"Add an interface/port to listen for connections (default all interfaces port: 49152, testnet: 59152)"`
	Version                  string
	HTTPSCert                string `long:"httpscert" description:"File containing the https certificate file"`
	HTTPSKey                 string `long:"httpskey" description:"File containing the https certificate key"`
	RPCHost                  string `long:"rpchost" description:"Host for politeiad in this format"`
	RPCCert                  string `long:"rpccert" description:"File containing the https certificate file"`
	DcrdataHost              string `long:"dcrdatahost" description:"Dcrdata ip:port"`
	RPCIdentityFile          string `long:"rpcidentityfile" description:"Path to file containing the politeiad identity"`
	Identity                 *identity.PublicIdentity
	RPCUser                  string `long:"rpcuser" description:"RPC user name for privileged commands"`
	RPCPass                  string `long:"rpcpass" description:"RPC password for privileged commands"`
	MailHost                 string `long:"mailhost" description:"Email server address in this format: <host>:<port>"`
	MailUser                 string `long:"mailuser" description:"Email server username"`
	MailPass                 string `long:"mailpass" description:"Email server password"`
	MailAddress              string `long:"mailaddress" description:"Email address for outgoing email in the format: name <address>"`
	DBHost                   string `long:"dbhost" description:"Database ip:port"`
	DBRootCert               string `long:"dbrootcert" description:"File containing the CA certificate for the database"`
	DBCert                   string `long:"dbcert" description:"File containing the politeiawww client certificate for the database"`
	DBKey                    string `long:"dbkey" description:"File containing the politeiawww client certificate key for the database"`
	BuildCMSDB               bool   `long:"buildcmsdb" description:"Build the cmsdb from scratch"`
	UserDB                   string `long:"userdb" description:"Database choice for the user database"`
	EncryptionKey            string `long:"encryptionkey" description:"File containing encryption key used for encrypting user data at rest"`
	OldEncryptionKey         string `long:"oldencryptionkey" description:"File containing old encryption key (only set when rotating keys)"`
	FetchIdentity            bool   `long:"fetchidentity" description:"Whether or not politeiawww fetches the identity from politeiad."`
	WebServerAddress         string `long:"webserveraddress" description:"Address for the Politeia web server; it should have this format: <scheme>://<host>[:<port>]"`
	Interactive              string `long:"interactive" description:"Set to i-know-this-is-a-bad-idea to turn off interactive mode during --fetchidentity."`
	PaywallAmount            uint64 `long:"paywallamount" description:"Amount of DCR (in atoms) required for a user to register or submit a proposal."`
	PaywallXpub              string `long:"paywallxpub" description:"Extended public key for deriving paywall addresses."`
	MinConfirmationsRequired uint64 `long:"minconfirmations" description:"Minimum blocks confirmation for accepting paywall as paid. Only works in TestNet."`
	VoteDurationMin          uint32 `long:"votedurationmin" description:"Minimum duration of a proposal vote in blocks"`
	VoteDurationMax          uint32 `long:"votedurationmax" description:"Maximum duration of a proposal vote in blocks"`
	AdminLogFile             string `long:"adminlogfile" description:"admin log filename (Default: admin.log)"`
	Mode                     string `long:"mode" description:"Mode www runs as. Supported values: piwww, cmswww"`
	SMTPSkipVerify           bool   `long:"smtpskipverify" description:"Skip SMTP TLS cert verification. Will only skip if SMTPCert is empty"`
	SMTPCert                 string `long:"smtpcert" description:"File containing the smtp certificate file"`
	SystemCerts              *x509.CertPool
}

// serviceOptions defines the configuration options for the rpc as a service
// on Windows.
type serviceOptions struct {
	ServiceCommand string `short:"s" long:"service" description:"Service command {install, remove, start, stop}"`
}

// cleanAndExpandPath expands environment variables and leading ~ in the
// passed path, cleans the result, and returns it.
func cleanAndExpandPath(path string) string {
	// Nothing to do when no path is given.
	if path == "" {
		return path
	}

	// NOTE: The os.ExpandEnv doesn't work with Windows cmd.exe-style
	// %VARIABLE%, but the variables can still be expanded via POSIX-style
	// $VARIABLE.
	path = os.ExpandEnv(path)

	if !strings.HasPrefix(path, "~") {
		return filepath.Clean(path)
	}

	// Expand initial ~ to the current user's home directory, or ~otheruser
	// to otheruser's home directory.  On Windows, both forward and backward
	// slashes can be used.
	path = path[1:]

	var pathSeparators string
	if runtime.GOOS == "windows" {
		pathSeparators = string(os.PathSeparator) + "/"
	} else {
		pathSeparators = string(os.PathSeparator)
	}

	userName := ""
	if i := strings.IndexAny(path, pathSeparators); i != -1 {
		userName = path[:i]
		path = path[i:]
	}

	homeDir := ""
	var u *user.User
	var err error
	if userName == "" {
		u, err = user.Current()
	} else {
		u, err = user.Lookup(userName)
	}
	if err == nil {
		homeDir = u.HomeDir
	}
	// Fallback to CWD if user lookup fails or user has no home directory.
	if homeDir == "" {
		homeDir = "."
	}

	return filepath.Join(homeDir, path)
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

// normalizeAddresses returns a new slice with all the passed peer addresses
// normalized with the given default port, and all duplicates removed.
func normalizeAddresses(addrs []string, defaultPort string) []string {
	for i, addr := range addrs {
		addrs[i] = util.NormalizeAddress(addr, defaultPort)
	}

	return removeDuplicateAddresses(addrs)
}

// filesExists reports whether the named file or directory exists.
func fileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// newConfigParser returns a new command line flags parser.
func newConfigParser(cfg *config, so *serviceOptions, options flags.Options) *flags.Parser {
	parser := flags.NewParser(cfg, options)
	if runtime.GOOS == "windows" {
		parser.AddGroup("Service Options", "Service Options", so)
	}
	return parser
}

// loadIdentity fetches an identity from politeiad if necessary.
func loadIdentity(cfg *config) error {
	// Set up the path to the politeiad identity file.
	if cfg.RPCIdentityFile == "" {
		cfg.RPCIdentityFile = filepath.Join(cfg.HomeDir,
			defaultIdentityFilename)
	} else {
		cfg.RPCIdentityFile = cleanAndExpandPath(cfg.RPCIdentityFile)
	}

	if cfg.FetchIdentity {
		// Don't try to load the identity from the existing file if the
		// caller is trying to fetch a new one.
		return nil
	}

	// Check if the identity already exists.
	if _, err := os.Stat(cfg.RPCIdentityFile); os.IsNotExist(err) {
		return fmt.Errorf("you must load the identity from politeiad " +
			"first using the --fetchidentity flag")
	}

	var err error
	cfg.Identity, err = identity.LoadPublicIdentity(cfg.RPCIdentityFile)
	if err != nil {
		return err
	}

	log.Infof("Identity loaded from: %v", cfg.RPCIdentityFile)
	return nil
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
func loadConfig() (*config, []string, error) {
	// Default config.
	cfg := config{
		HomeDir:                  sharedconfig.DefaultHomeDir,
		ConfigFile:               sharedconfig.DefaultConfigFile,
		DebugLevel:               defaultLogLevel,
		DataDir:                  sharedconfig.DefaultDataDir,
		LogDir:                   defaultLogDir,
		HTTPSKey:                 defaultHTTPSKeyFile,
		HTTPSCert:                defaultHTTPSCertFile,
		RPCCert:                  defaultRPCCertFile,
		CookieKeyFile:            defaultCookieKeyFile,
		PaywallAmount:            defaultPaywallAmount,
		MinConfirmationsRequired: defaultPaywallMinConfirmations,
		Version:                  version.String(),
		VoteDurationMin:          defaultVoteDurationMin,
		VoteDurationMax:          defaultVoteDurationMax,
		MailAddress:              defaultMailAddress,
		Mode:                     defaultWWWMode,
		UserDB:                   defaultUserDB,
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

	// Update the home directory for stakepoold if specified. Since the
	// home directory is updated, other variables need to be updated to
	// reflect the new changes.
	if preCfg.HomeDir != "" {
		cfg.HomeDir, _ = filepath.Abs(preCfg.HomeDir)

		if preCfg.ConfigFile == sharedconfig.DefaultConfigFile {
			cfg.ConfigFile = filepath.Join(cfg.HomeDir, sharedconfig.DefaultConfigFilename)
		} else {
			cfg.ConfigFile = preCfg.ConfigFile
		}
		if preCfg.DataDir == sharedconfig.DefaultDataDir {
			cfg.DataDir = filepath.Join(cfg.HomeDir, sharedconfig.DefaultDataDirname)
		} else {
			cfg.DataDir = preCfg.DataDir
		}
		if preCfg.HTTPSKey == defaultHTTPSKeyFile {
			cfg.HTTPSKey = filepath.Join(cfg.HomeDir, "https.key")
		} else {
			cfg.HTTPSKey = preCfg.HTTPSKey
		}
		if preCfg.HTTPSCert == defaultHTTPSCertFile {
			cfg.HTTPSCert = filepath.Join(cfg.HomeDir, "https.cert")
		} else {
			cfg.HTTPSCert = preCfg.HTTPSCert
		}
		if preCfg.RPCCert == defaultRPCCertFile {
			cfg.RPCCert = filepath.Join(cfg.HomeDir, "rpc.cert")
		} else {
			cfg.RPCCert = preCfg.RPCCert
		}
		if preCfg.LogDir == defaultLogDir {
			cfg.LogDir = filepath.Join(cfg.HomeDir, defaultLogDirname)
		} else {
			cfg.LogDir = preCfg.LogDir
		}
		if preCfg.CookieKeyFile == defaultCookieKeyFile {
			cfg.CookieKeyFile = filepath.Join(cfg.HomeDir, "cookie.key")
		} else {
			cfg.CookieKeyFile = preCfg.CookieKeyFile
		}
	}

	// Load additional config from file.
	var configFileError error
	parser := newConfigParser(&cfg, &serviceOpts, flags.Default)
	if !(preCfg.SimNet) || cfg.ConfigFile != sharedconfig.DefaultConfigFile {
		err := flags.NewIniParser(parser).ParseFile(cfg.ConfigFile)
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

	// Verify mode
	switch cfg.Mode {
	case cmsWWWMode:
		if cfg.MailAddress == defaultMailAddress {
			cfg.MailAddress = defaultCMSMailAddress
		}
	case politeiaWWWMode:
	default:
		err := fmt.Errorf("invalid mode: %v", cfg.Mode)
		fmt.Fprintln(os.Stderr, err)
		return nil, nil, err
	}

	// Verify mail address
	if _, err := mail.ParseAddress(cfg.MailAddress); err != nil {
		err := fmt.Errorf("invalid mailaddress: %v", err)
		fmt.Fprintln(os.Stderr, err)
		return nil, nil, err
	}

	// Create the home directory if it doesn't already exist.
	funcName := "loadConfig"
	err = os.MkdirAll(sharedconfig.DefaultHomeDir, 0700)
	if err != nil {
		// Show a nicer error message if it's because a symlink is
		// linked to a directory that does not exist (probably because
		// it's not mounted).
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

	// Multiple networks can't be selected simultaneously.
	numNets := 0

	// Count number of network flags passed; assign active network params
	// while we're at it
	port := defaultMainnetPort
	activeNetParams = &mainNetParams
	if cfg.TestNet {
		numNets++
		activeNetParams = &testNet3Params
		port = defaultTestnetPort
	}
	if cfg.SimNet {
		numNets++
		// Also disable dns seeding on the simulation test network.
		activeNetParams = &simNetParams
	}
	if numNets > 1 {
		str := "%s: The testnet and simnet params can't be " +
			"used together -- choose one of the three"
		err := fmt.Errorf(str, funcName)
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, usageMessage)
		return nil, nil, err
	}

	// Append the network type to the data directory so it is "namespaced"
	// per network.  In addition to the block database, there are other
	// pieces of data that are saved to disk such as address manager state.
	// All data is specific to a network, so namespacing the data directory
	// means each individual piece of serialized data does not have to
	// worry about changing names per network and such.
	cfg.DataDir = cleanAndExpandPath(cfg.DataDir)
	cfg.DataDir = filepath.Join(cfg.DataDir, netName(activeNetParams))

	// Append the network type to the log directory so it is "namespaced"
	// per network in the same fashion as the data directory.
	cfg.LogDir = cleanAndExpandPath(cfg.LogDir)
	cfg.LogDir = filepath.Join(cfg.LogDir, netName(activeNetParams))

	cfg.AdminLogFile = filepath.Join(cfg.LogDir, adminLogFilename)

	cfg.HTTPSKey = cleanAndExpandPath(cfg.HTTPSKey)
	cfg.HTTPSCert = cleanAndExpandPath(cfg.HTTPSCert)
	cfg.RPCCert = cleanAndExpandPath(cfg.RPCCert)

	// Validate cache options.
	switch {
	case cfg.DBHost == "":
		return nil, nil, fmt.Errorf("dbhost param is required")
	case cfg.DBRootCert == "":
		return nil, nil, fmt.Errorf("dbrootcert param is required")
	case cfg.DBCert == "":
		return nil, nil, fmt.Errorf("dbcert param is required")
	case cfg.DBKey == "":
		return nil, nil, fmt.Errorf("dbkey param is required")
	}

	cfg.DBRootCert = cleanAndExpandPath(cfg.DBRootCert)
	cfg.DBCert = cleanAndExpandPath(cfg.DBCert)
	cfg.DBKey = cleanAndExpandPath(cfg.DBKey)

	// Validate db host.
	_, err = url.Parse(cfg.DBHost)
	if err != nil {
		return nil, nil, fmt.Errorf("parse dbhost: %v", err)
	}

	// Validate db root cert.
	b, err := ioutil.ReadFile(cfg.DBRootCert)
	if err != nil {
		return nil, nil, fmt.Errorf("read dbrootcert: %v", err)
	}
	block, _ := pem.Decode(b)
	_, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse dbrootcert: %v", err)
	}

	// Validate db key pair.
	_, err = tls.LoadX509KeyPair(cfg.DBCert, cfg.DBKey)
	if err != nil {
		return nil, nil, fmt.Errorf("load key pair dbcert "+
			"and dbkey: %v", err)
	}

	// Validate user database selection.
	switch cfg.UserDB {
	case userDBLevel, userDBCockroach:
		// Valid selection; continue
	default:
		return nil, nil, fmt.Errorf("invalid userdb '%v'; must "+
			"be either leveldb or cockroachdb", cfg.UserDB)
	}

	// Validate encryption keys.
	cfg.EncryptionKey = cleanAndExpandPath(cfg.EncryptionKey)
	cfg.OldEncryptionKey = cleanAndExpandPath(cfg.OldEncryptionKey)

	if cfg.EncryptionKey != "" {
		if cfg.UserDB == userDBLevel {
			return nil, nil, fmt.Errorf("data at rest encryption is not" +
				"currently supported for leveldb; remove encryption key " +
				"param or change user database param")
		}

		if !util.FileExists(cfg.EncryptionKey) {
			return nil, nil, fmt.Errorf("file not found %v",
				cfg.EncryptionKey)
		}
	}

	if cfg.OldEncryptionKey != "" {
		if cfg.EncryptionKey == "" {
			return nil, nil, fmt.Errorf("old encryption key param " +
				"cannot be used without encryption key param")
		}

		if cfg.EncryptionKey == cfg.OldEncryptionKey {
			return nil, nil, fmt.Errorf("old encryption key param " +
				"and encryption key param must be different")
		}

		if !util.FileExists(cfg.OldEncryptionKey) {
			return nil, nil, fmt.Errorf("file not found %v",
				cfg.OldEncryptionKey)
		}
	}

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

	// Add the default listener if none were specified. The default
	// listener is all addresses on the listen port for the network
	// we are to connect to.
	if len(cfg.Listeners) == 0 {
		cfg.Listeners = []string{
			net.JoinHostPort("", port),
		}
	}

	// Add default port to all listener addresses if needed and remove
	// duplicate addresses.
	cfg.Listeners = normalizeAddresses(cfg.Listeners, port)

	// Set up the rpc address.
	if cfg.TestNet {
		port = v1.DefaultTestnetPort
		if cfg.RPCHost == "" {
			cfg.RPCHost = v1.DefaultTestnetHost
		}
	} else {
		port = v1.DefaultMainnetPort
		if cfg.RPCHost == "" {
			cfg.RPCHost = v1.DefaultMainnetHost
		}
		if cfg.MinConfirmationsRequired != defaultPaywallMinConfirmations {
			return nil, nil, fmt.Errorf("[ERR]: Can not change min block " +
				"confirmations when in mainnet")
		}
	}

	// Setup dcrdata addresses
	if cfg.DcrdataHost == "" {
		if cfg.TestNet {
			cfg.DcrdataHost = defaultDcrdataTestnet
		} else {
			cfg.DcrdataHost = defaultDcrdataMainnet
		}
	}

	cfg.RPCHost = util.NormalizeAddress(cfg.RPCHost, port)
	u, err := url.Parse("https://" + cfg.RPCHost)
	if err != nil {
		return nil, nil, err
	}
	cfg.RPCHost = u.String()

	// Set random username and password when not specified
	if cfg.RPCUser == "" {
		name, err := util.Random(32)
		if err != nil {
			return nil, nil, err
		}
		cfg.RPCUser = base64.StdEncoding.EncodeToString(name)
		log.Warnf("RPC user name not set, using random value")
	}
	if cfg.RPCPass == "" {
		pass, err := util.Random(32)
		if err != nil {
			return nil, nil, err
		}
		cfg.RPCPass = base64.StdEncoding.EncodeToString(pass)
		log.Warnf("RPC password not set, using random value")
	}

	// Valide mail settings
	switch {
	case cfg.MailHost == "" && cfg.MailUser == "" &&
		cfg.MailPass == "" && cfg.WebServerAddress == "":
		// Email is disabled; this is ok
	case cfg.MailHost != "" && cfg.MailUser != "" &&
		cfg.MailPass != "" && cfg.WebServerAddress != "":
		// All mail settings have been set; this is ok
	default:
		return nil, nil, fmt.Errorf("either all or none of the " +
			"following config options should be supplied: " +
			"mailhost, mailuser, mailpass, webserveraddress")
	}

	u, err = url.Parse(cfg.MailHost)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse mail host: %v",
			err)
	}
	cfg.MailHost = u.String()

	a, err := mail.ParseAddress(cfg.MailAddress)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse mail address: %v",
			err)
	}
	cfg.MailAddress = a.String()

	u, err = url.Parse(cfg.WebServerAddress)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse web server address: %v",
			err)
	}
	cfg.WebServerAddress = u.String()

	// Load identity
	if err := loadIdentity(&cfg); err != nil {
		return nil, nil, err
	}

	// Warn about missing config file only after all other configuration is
	// done.  This prevents the warning on help messages and invalid
	// options.  Note this should go directly before the return.
	if configFileError != nil {
		log.Warnf("%v", configFileError)
	}

	// Parse the extended public key if the paywall is enabled.
	if cfg.PaywallAmount != 0 || cfg.PaywallXpub != "" {
		if cfg.PaywallAmount < dust {
			return nil, nil, fmt.Errorf("[ERR]: Paywall amount needs to be "+
				"higher than %v", dust)
		}
		_, err := hdkeychain.NewKeyFromString(cfg.PaywallXpub, activeNetParams.Params)
		if err != nil {
			return nil, nil, fmt.Errorf("error processing extended public key: %v",
				err)
		}
	}

	// Validate smtp root cert.
	if cfg.SMTPCert != "" {
		cfg.SMTPCert = cleanAndExpandPath(cfg.SMTPCert)

		b, err := ioutil.ReadFile(cfg.SMTPCert)
		if err != nil {
			return nil, nil, fmt.Errorf("read smtpcert: %v", err)
		}
		block, _ := pem.Decode(b)
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parse smtpcert: %v", err)
		}
		systemCerts, err := x509.SystemCertPool()
		if err != nil {
			return nil, nil, fmt.Errorf("getting systemcertpool: %v", err)
		}
		systemCerts.AddCert(cert)
		cfg.SystemCerts = systemCerts

		if cfg.SMTPSkipVerify {
			log.Warnf("SMTPCert has been set so SMTPSkipVerify is being disregarded.")
		}
	}

	return &cfg, remainingArgs, nil
}

func (p *politeiawww) dcrdataHostHTTP() string {
	return fmt.Sprintf("https://%v/api", p.cfg.DcrdataHost)
}

func (p *politeiawww) dcrdataHostWS() string {
	return fmt.Sprintf("wss://%v/ps", p.cfg.DcrdataHost)
}
