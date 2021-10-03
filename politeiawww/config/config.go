// Copyright (c) 2013-2014 The btcsuite developers
// Copyright (c) 2015-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package config

import (
	"crypto/tls"
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
	"time"

	"github.com/decred/dcrd/dcrutil/v3"
	"github.com/decred/dcrd/hdkeychain/v3"
	v1 "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiawww/logger"
	"github.com/decred/politeia/util"
	"github.com/decred/politeia/util/version"
	"github.com/jessevdk/go-flags"
)

const (
	// DefaultConfigFilename is the default configuration file name.
	DefaultConfigFilename = "politeiawww.conf"

	// DefaultDataDirname is the default data directory name. The data
	// directory is located in the application home directory.
	DefaultDataDirname = "data"

	// Currently available modes to run politeia, by default piwww, is
	// used.
	PoliteiaWWWMode = "piwww"
	CMSWWWMode      = "cmswww"

	// Database options
	LevelDB     = "leveldb"
	CockroachDB = "cockroachdb"
	MySQL       = "mysql"

	defaultLogLevel         = "info"
	defaultLogDirname       = "logs"
	defaultLogFilename      = "politeiawww.log"
	defaultIdentityFilename = "identity.json"

	defaultMainnetPort = "4443"
	defaultTestnetPort = "4443"

	defaultPaywallMinConfirmations = uint64(2)
	defaultPaywallAmount           = uint64(0)

	defaultVoteDurationMin = uint32(2016)
	defaultVoteDurationMax = uint32(4032)

	defaultMailAddressPi  = "Politeia <noreply@example.org>"
	defaultMailAddressCMS = "Contractor Management System <noreply@example.org>"

	defaultDcrdataMainnet = "dcrdata.decred.org:443"
	defaultDcrdataTestnet = "testnet.decred.org:443"

	// dust value can be found increasing the amount value until we get false
	// from IsDustAmount function. Amounts can not be lower than dust
	// func IsDustAmount(amount int64, relayFeePerKb int64) bool {
	//     totalSize := 8 + 2 + 1 + 25 + 165
	// 	   return int64(amount)*1000/(3*int64(totalSize)) < int64(relayFeePerKb)
	// }
	dust = 60300

	defaultWWWMode = PoliteiaWWWMode

	defaultUserDB          = LevelDB
	defaultMySQLDBHost     = "localhost:3306"  // MySQL default host
	defaultCockroachDBHost = "localhost:26257" // CockroachDB default host

	defaultMailRateLimit = 100 // Email limit per user

	// Environment variables.
	envDBPass = "DBPASS"
)

var (
	// DefaultHomeDir points to politeiawww's default home directory.
	DefaultHomeDir = dcrutil.AppDataDir("politeiawww", false)

	// DefaultConfigFile points to politeiawww's default config file
	// path.
	DefaultConfigFile = filepath.Join(DefaultHomeDir, DefaultConfigFilename)

	// DefaultDataDir points to politeiawww's default data directory
	// path.
	DefaultDataDir = filepath.Join(DefaultHomeDir, DefaultDataDirname)

	// DefaultHTTPSCertFile contains the file path to the politeiawww
	// https certificate.
	DefaultHTTPSCertFile = filepath.Join(DefaultHomeDir, "https.cert")

	defaultEncryptionKey = filepath.Join(DefaultHomeDir, "sbox.key")
	defaultHTTPSKeyFile  = filepath.Join(DefaultHomeDir, "https.key")
	defaultRPCCertFile   = filepath.Join(DefaultHomeDir, "rpc.cert")
	defaultCookieKeyFile = filepath.Join(DefaultHomeDir, "cookie.key")
	defaultLogDir        = filepath.Join(DefaultHomeDir, defaultLogDirname)

	// defaultReadTimeout is the maximum duration in seconds that is spent
	// reading the request headers and body.
	defaultReadTimeout int64 = 5

	// defaultWriteTimeout is the maximum duration in seconds that a request
	// connection is kept open.
	defaultWriteTimeout int64 = 60

	// defaultReqBodySizeLimit is the maximum number of bytes allowed in a
	// request body.
	defaultReqBodySizeLimit int64 = 3 * 1024 * 1024 // 3 MiB

	// defaultWebsocketReadLimit is the maximum number of bytes allowed for a
	// message read from a websocket client.
	defaultWebsocketReadLimit int64 = 4 * 1024 * 1024 // 4 KiB

	// Default start date to start pulling code statistics if none specified.
	defaultCodeStatStart = time.Now().Add(-1 * time.Minute * 60 * 24 * 7 * 26) // 6 months in minutes 60min * 24h * 7days * 26 weeks

	// Default end date to stop pull code statistics if none specified.
	defaultCodeStatEnd = time.Now() // Use today as the default end code stat date

	// Check to make sure code stat start time is sane 2 years from today.
	codeStatCheck = time.Now().Add(-1 * time.Minute * 60 * 24 * 7 * 52 * 2) // 2 years in minutes 60min * 24h * 7days * 52weeks * 2years
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
	ReqBodySizeLimit   int64    `long:"reqbodysizelimit" description:"Maximum number of bytes allowed for a request body from a http client"`
	WebsocketReadLimit int64    `long:"websocketreadlimit" description:"Maximum number of bytes allowed for a message read from a websocket client"`

	// politeiad RPC settings
	RPCHost         string `long:"rpchost" description:"Host for politeiad in this format"`
	RPCCert         string `long:"rpccert" description:"File containing the https certificate file"`
	RPCIdentityFile string `long:"rpcidentityfile" description:"Path to file containing the politeiad identity"`
	RPCUser         string `long:"rpcuser" description:"RPC user name for privileged politeaid commands"`
	RPCPass         string `long:"rpcpass" description:"RPC password for privileged politeiad commands"`
	FetchIdentity   bool   `long:"fetchidentity" description:"Whether or not politeiawww fetches the identity from politeiad."`
	Interactive     string `long:"interactive" description:"Set to i-know-this-is-a-bad-idea to turn off interactive mode during --fetchidentity."`

	// User database settings
	UserDB string `long:"userdb" description:"Database choice for the user database"`
	DBHost string `long:"dbhost" description:"Database ip:port"`
	DBPass string // Provided in env variable "DBPASS"

	// Legacy user database settings. These need to be removed.
	DBRootCert       string `long:"dbrootcert" description:"File containing the CA certificate for the database"`
	DBCert           string `long:"dbcert" description:"File containing the politeiawww client certificate for the database"`
	DBKey            string `long:"dbkey" description:"File containing the politeiawww client certificate key for the database"`
	EncryptionKey    string `long:"encryptionkey" description:"File containing encryption key used for encrypting user data at rest"`
	OldEncryptionKey string `long:"oldencryptionkey" description:"File containing old encryption key (only set when rotating keys)"`

	// SMTP settings
	MailHost string `long:"mailhost" description:"Email server address in
	this format: <host>:<port>"`
	MailUser       string `long:"mailuser" description:"Email server username"`
	MailPass       string `long:"mailpass" description:"Email server password"`
	MailAddress    string `long:"mailaddress" description:"Email address for outgoing email in the format: name <address>"`
	MailCert       string `long:"mailcert" description:"Email server certificate file"`
	MailSkipVerify bool   `long:"mailskipverify" description:"Skip TLS verification when connecting to the mail server"`

	// SMTP settings the need to be turned into plugin settings.
	MailRateLimit    int    `long:"mailratelimit" description:"Limits the amount of emails a user can receive in 24h"`
	WebServerAddress string `long:"webserveraddress" description:"Web server address used to create email links (format: <scheme>://<host>[:<port>])"`

	// Legacy API settings. These need to be removed and converted into plugin
	// settings.
	Mode                     string   `long:"mode" description:"Mode www runs as. Supported values: piwww, cmswww"`
	DcrdataHost              string   `long:"dcrdatahost" description:"Dcrdata ip:port"`
	PaywallAmount            uint64   `long:"paywallamount" description:"Amount of DCR (in atoms) required for a user to register or submit a proposal."`
	PaywallXpub              string   `long:"paywallxpub" description:"Extended public key for deriving paywall addresses."`
	MinConfirmationsRequired uint64   `long:"minconfirmations" description:"Minimum blocks confirmation for accepting paywall as paid. Only works in TestNet."`
	BuildCMSDB               bool     `long:"buildcmsdb" description:"Build the cmsdb from scratch"`
	GithubAPIToken           string   `long:"githubapitoken" description:"API Token used to communicate with github API.  When populated in cmswww mode, github-tracker is enabled."`
	CodeStatRepos            []string `long:"codestatrepos" description:"Org/Repositories to crawl for code statistics"`
	CodeStatOrganization     string   `long:"codestatorg" description:"Organization to crawl for code statistics"`
	CodeStatStart            int64    `long:"codestatstart" description:"Date in which to look back to for code stat crawl (default 6 months back)"`
	CodeStatEnd              int64    `long:"codestatend" description:"Date in which to end look back to for code stat crawl (default today)"`
	CodeStatSkipSync         bool     `long:"codestatskipsync" description:"Skip pull request crawl on startup"`
	VoteDurationMin          uint32   `long:"votedurationmin" description:"Minimum duration of a dcc vote in blocks"`
	VoteDurationMax          uint32   `long:"votedurationmax" description:"Maximum duration of a dcc vote in blocks"`

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
	// Default config.
	cfg := Config{
		// General application settings
		HomeDir:    DefaultHomeDir,
		ConfigFile: DefaultConfigFile,
		DataDir:    DefaultDataDir,
		LogDir:     defaultLogDir,
		DebugLevel: defaultLogLevel,

		// HTTP server settings
		HTTPSCert:          DefaultHTTPSCertFile,
		HTTPSKey:           defaultHTTPSKeyFile,
		CookieKeyFile:      defaultCookieKeyFile,
		ReadTimeout:        defaultReadTimeout,
		WriteTimeout:       defaultWriteTimeout,
		ReqBodySizeLimit:   defaultReqBodySizeLimit,
		WebsocketReadLimit: defaultWebsocketReadLimit,

		// politeiad RPC settings
		RPCCert: defaultRPCCertFile,

		// User database settings
		UserDB: defaultUserDB,

		// Legacy settings
		Mode:                     defaultWWWMode,
		PaywallAmount:            defaultPaywallAmount,
		MinConfirmationsRequired: defaultPaywallMinConfirmations,
		VoteDurationMin:          defaultVoteDurationMin,
		VoteDurationMax:          defaultVoteDurationMax,
		MailRateLimit:            defaultMailRateLimit,

		// Other
		Version: version.String(),
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

		if preCfg.ConfigFile == DefaultConfigFile {
			cfg.ConfigFile = filepath.Join(cfg.HomeDir, DefaultConfigFilename)
		} else {
			cfg.ConfigFile = preCfg.ConfigFile
		}
		if preCfg.DataDir == DefaultDataDir {
			cfg.DataDir = filepath.Join(cfg.HomeDir, DefaultDataDirname)
		} else {
			cfg.DataDir = preCfg.DataDir
		}
		if preCfg.HTTPSKey == defaultHTTPSKeyFile {
			cfg.HTTPSKey = filepath.Join(cfg.HomeDir, "https.key")
		} else {
			cfg.HTTPSKey = preCfg.HTTPSKey
		}
		if preCfg.HTTPSCert == DefaultHTTPSCertFile {
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

	// Verify mode and set mode specific defaults
	switch cfg.Mode {
	case CMSWWWMode:
		if cfg.MailAddress == "" {
			cfg.MailAddress = defaultMailAddressCMS
		}
	case PoliteiaWWWMode:
		if cfg.MailAddress == "" {
			cfg.MailAddress = defaultMailAddressPi
		}
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
	err = os.MkdirAll(DefaultHomeDir, 0700)
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

	// Assign active network params.
	port := defaultMainnetPort
	cfg.ActiveNet = &mainNetParams
	if cfg.TestNet {
		cfg.ActiveNet = &testNet3Params
		port = defaultTestnetPort
	}

	// Append the network type to the data directory so it is "namespaced"
	// per network.  In addition to the block database, there are other
	// pieces of data that are saved to disk such as address manager state.
	// All data is specific to a network, so namespacing the data directory
	// means each individual piece of serialized data does not have to
	// worry about changing names per network and such.
	cfg.DataDir = util.CleanAndExpandPath(cfg.DataDir)
	cfg.DataDir = filepath.Join(cfg.DataDir, netName(cfg.ActiveNet))

	// Append the network type to the log directory so it is "namespaced"
	// per network in the same fashion as the data directory.
	cfg.LogDir = util.CleanAndExpandPath(cfg.LogDir)
	cfg.LogDir = filepath.Join(cfg.LogDir, netName(cfg.ActiveNet))

	cfg.HTTPSKey = util.CleanAndExpandPath(cfg.HTTPSKey)
	cfg.HTTPSCert = util.CleanAndExpandPath(cfg.HTTPSCert)
	cfg.RPCCert = util.CleanAndExpandPath(cfg.RPCCert)

	if cfg.CodeStatStart > 0 &&
		(time.Unix(cfg.CodeStatStart, 0).Before(codeStatCheck) ||
			time.Unix(cfg.CodeStatStart, 0).After(time.Now())) {
		return nil, nil, fmt.Errorf("you have entered an invalid code stat " +
			"start date")
	}

	if cfg.CodeStatEnd > 0 &&
		time.Unix(cfg.CodeStatEnd, 0).Before(time.Unix(cfg.CodeStatStart, 0)) {
		return nil, nil, fmt.Errorf("you have entered an invalid code stat " +
			"end date")
	}

	if cfg.CodeStatStart <= 0 {
		cfg.CodeStatStart = defaultCodeStatStart.Unix()
	}

	if cfg.CodeStatEnd <= 0 {
		cfg.CodeStatEnd = defaultCodeStatEnd.Unix()
	}

	// Special show command to list supported subsystems and exit.
	if cfg.DebugLevel == "show" {
		fmt.Println("Supported subsystems", logger.SupportedSubsystems())
		os.Exit(0)
	}

	// Initialize log rotation.  After log rotation has been initialized,
	// the logger variables may be used.
	logger.InitLogRotator(filepath.Join(cfg.LogDir, defaultLogFilename))

	// Parse, validate, and set debug log level(s).
	if err := parseAndSetDebugLevels(cfg.DebugLevel); err != nil {
		err := fmt.Errorf("%s: %v", funcName, err.Error())
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, usageMessage)
		return nil, nil, err
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

	// Set up the politeiad rpc address.
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
	}

	// Verify politeiad RPC settings
	cfg.RPCHost = util.NormalizeAddress(cfg.RPCHost, port)
	u, err := url.Parse("https://" + cfg.RPCHost)
	if err != nil {
		return nil, nil, err
	}
	cfg.RPCHost = u.String()

	if cfg.RPCUser == "" {
		return nil, nil, fmt.Errorf("politeiad rpc user must be provided " +
			"with --rpcuser")
	}
	if cfg.RPCPass == "" {
		return nil, nil, fmt.Errorf("politeiad rpc pass must be provided " +
			"with --rpcpass")
	}

	// Verify mail settings
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
		return nil, nil, fmt.Errorf("unable to parse mail host: %v", err)
	}
	cfg.MailHost = u.String()

	a, err := mail.ParseAddress(cfg.MailAddress)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse mail address: %v", err)
	}
	cfg.MailAddress = a.String()

	u, err = url.Parse(cfg.WebServerAddress)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse web server address: %v", err)
	}
	cfg.WebServerAddress = u.String()

	// Validate smtp root cert.
	if cfg.MailCert != "" {
		cfg.MailCert = util.CleanAndExpandPath(cfg.MailCert)

		b, err := ioutil.ReadFile(cfg.MailCert)
		if err != nil {
			return nil, nil, fmt.Errorf("read mailcert: %v", err)
		}
		block, _ := pem.Decode(b)
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parse mailcert: %v", err)
		}
		systemCerts, err := x509.SystemCertPool()
		if err != nil {
			return nil, nil, fmt.Errorf("getting systemcertpool: %v", err)
		}
		systemCerts.AddCert(cert)
		cfg.SystemCerts = systemCerts

		if cfg.MailSkipVerify && cfg.MailCert != "" {
			return nil, nil, fmt.Errorf("cannot set MailSkipVerify and provide " +
				"a MailCert at the same time")
		}
	}

	// Validate user database selection.
	switch cfg.UserDB {
	case LevelDB:
		// Leveldb implementation does not require any database settings
		// and does support encrypting data at rest. Return an error if
		// the user has the encryption settings set to prevent them from
		// thinking their data is being encrypted.
		switch {
		case cfg.DBHost != "":
			log.Warnf("leveldb does not use --dbhost")
		case cfg.DBRootCert != "":
			log.Warnf("leveldb does not use --dbrootcert")
		case cfg.DBCert != "":
			log.Warnf("leveldb does not use --dbcert")
		case cfg.DBKey != "":
			log.Warnf("leveldb does not use --dbkey")
		case cfg.EncryptionKey != "":
			return nil, nil, fmt.Errorf("leveldb --encryptionkey not supported")
		case cfg.OldEncryptionKey != "":
			return nil, nil, fmt.Errorf("leveldb --oldencryptionkey not supported")
		}

	case CockroachDB:
		// Cockroachdb requires these settings.
		switch {
		case cfg.DBRootCert == "":
			return nil, nil, fmt.Errorf("dbrootcert param is required")
		case cfg.DBCert == "":
			return nil, nil, fmt.Errorf("dbcert param is required")
		case cfg.DBKey == "":
			return nil, nil, fmt.Errorf("dbkey param is required")
		}

		// Set default DBHost if not set.
		if cfg.DBHost == "" {
			cfg.DBHost = defaultCockroachDBHost
		}

		// Validate DB host.
		err = validateDBHost(cfg.DBHost)
		if err != nil {
			return nil, nil, err
		}

		// Set default encryption key path if not set.
		if cfg.EncryptionKey == "" {
			cfg.EncryptionKey = defaultEncryptionKey
		}

		// Clean user database settings
		cfg.DBRootCert = util.CleanAndExpandPath(cfg.DBRootCert)
		cfg.DBCert = util.CleanAndExpandPath(cfg.DBCert)
		cfg.DBKey = util.CleanAndExpandPath(cfg.DBKey)
		cfg.EncryptionKey = util.CleanAndExpandPath(cfg.EncryptionKey)
		cfg.OldEncryptionKey = util.CleanAndExpandPath(cfg.OldEncryptionKey)

		// Validate user database encryption keys.
		err = validateEncryptionKeys(cfg.EncryptionKey, cfg.OldEncryptionKey)
		if err != nil {
			return nil, nil, fmt.Errorf("validate encryption keys: %v", err)
		}

		// Validate user database root cert
		b, err := ioutil.ReadFile(cfg.DBRootCert)
		if err != nil {
			return nil, nil, fmt.Errorf("read dbrootcert: %v", err)
		}
		block, _ := pem.Decode(b)
		_, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parse dbrootcert: %v", err)
		}

		// Validate user database key pair
		_, err = tls.LoadX509KeyPair(cfg.DBCert, cfg.DBKey)
		if err != nil {
			return nil, nil, fmt.Errorf("load key pair dbcert "+
				"and dbkey: %v", err)
		}

	case MySQL:
		// The database password is provided in an env variable.
		cfg.DBPass = os.Getenv(envDBPass)
		if cfg.DBPass == "" {
			return nil, nil, fmt.Errorf("dbpass not found; you must provide " +
				"the database password for the politeiawww user in the env " +
				"variable DBPASS")
		}

		// Set default DBHost if not set.
		if cfg.DBHost == "" {
			cfg.DBHost = defaultMySQLDBHost
		}

		// Validate DB host.
		err = validateDBHost(cfg.DBHost)
		if err != nil {
			return nil, nil, err
		}

		// Set default encryption key path if not set.
		if cfg.EncryptionKey == "" {
			cfg.EncryptionKey = defaultEncryptionKey
		}

		// Clean encryption keys paths.
		cfg.EncryptionKey = util.CleanAndExpandPath(cfg.EncryptionKey)
		cfg.OldEncryptionKey = util.CleanAndExpandPath(cfg.OldEncryptionKey)

		// Validate user database encryption keys.
		err = validateEncryptionKeys(cfg.EncryptionKey, cfg.OldEncryptionKey)
		if err != nil {
			return nil, nil, fmt.Errorf("validate encryption keys: %v", err)
		}

	default:
		return nil, nil, fmt.Errorf("invalid userdb '%v'; must "+
			"be leveldb, cockroachdb or mysql", cfg.UserDB)
	}

	// Verify paywall settings
	paywallIsEnabled := cfg.PaywallAmount != 0 || cfg.PaywallXpub != ""
	if paywallIsEnabled {
		// Parse extended public key
		_, err := hdkeychain.NewKeyFromString(cfg.PaywallXpub,
			cfg.ActiveNet.Params)
		if err != nil {
			return nil, nil, fmt.Errorf("error processing extended "+
				"public key: %v", err)
		}

		// Verify paywall amount
		if cfg.PaywallAmount < dust {
			return nil, nil, fmt.Errorf("paywall amount needs to be "+
				"higher than %v", dust)
		}

		// Verify required paywall confirmations
		if !cfg.TestNet &&
			cfg.MinConfirmationsRequired != defaultPaywallMinConfirmations {
			return nil, nil, fmt.Errorf("cannot set --minconfirmations on mainnet")
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

	return &cfg, remainingArgs, nil
}

// runServiceCommand is only set to a real function on Windows.  It is used
// to parse and execute service commands specified via the -s flag.
var runServiceCommand func(string) error

// serviceOptions defines the configuration options for the rpc as a service
// on Windows.
type serviceOptions struct {
	ServiceCommand string `short:"s" long:"service" description:"Service command {install, remove, start, stop}"`
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

// newConfigParser returns a new command line flags parser.
func newConfigParser(cfg *Config, so *serviceOptions, options flags.Options) *flags.Parser {
	parser := flags.NewParser(cfg, options)
	if runtime.GOOS == "windows" {
		parser.AddGroup("Service Options", "Service Options", so)
	}
	return parser
}

// loadIdentity loads the politeiad identity from disk. An error is returned if
// an identity is not found, instructing the user to fetch the politeiad
// identity with the --fetchidentity flag.
func loadIdentity(cfg *Config) error {
	// Set up the path to the politeiad identity file.
	if cfg.RPCIdentityFile == "" {
		cfg.RPCIdentityFile = filepath.Join(cfg.HomeDir,
			defaultIdentityFilename)
	} else {
		cfg.RPCIdentityFile = util.CleanAndExpandPath(cfg.RPCIdentityFile)
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

// validateEncryptionKeys validates the encryption keys config and returns
// the keys' cleaned paths.
func validateEncryptionKeys(encKey, oldEncKey string) error {
	if encKey != "" && !util.FileExists(encKey) {
		return fmt.Errorf("file not found %v", encKey)
	}

	if oldEncKey != "" {
		switch {
		case encKey == "":
			return fmt.Errorf("old encryption key param " +
				"cannot be used without encryption key param")

		case encKey == oldEncKey:
			return fmt.Errorf("old encryption key param " +
				"and encryption key param must be different")

		case !util.FileExists(oldEncKey):
			return fmt.Errorf("file not found %v", oldEncKey)
		}
	}

	return nil
}

// validateDBHost validates user database host.
func validateDBHost(host string) error {
	if host == "" {
		return fmt.Errorf("dbhost param is required")
	}

	_, err := url.Parse(host)
	if err != nil {
		return fmt.Errorf("parse dbhost: %v", err)
	}

	return nil
}
