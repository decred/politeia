package config

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io/ioutil"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"

	flags "github.com/btcsuite/go-flags"
	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiawww/sharedconfig"
	"github.com/decred/politeia/util/version"
)

const (
	defaultHomeDirname       = "cli"
	defaultConfigFilename    = "politeiawwwcli.conf"
	defaultHost              = "https://proposals.decred.org/api"
	defaultFaucetHost        = "https://faucet.decred.org/requestfaucet"
	defaultWalletHost        = "127.0.0.1"
	defaultWalletMainnetPort = "19110" // we don't allow mainnet for right now
	defaultWalletTestnetPort = "19111"

	cookieFilePrefix   = "cookie_"
	identityFilePrefix = "identity_"
	csrfFilePrefix     = "csrf_"
)

var (
	defaultHomeDir        = filepath.Join(sharedconfig.DefaultHomeDir, defaultHomeDirname)
	defaultConfigFile     = filepath.Join(defaultHomeDir, defaultConfigFilename)
	defaultCookieFile     = filePath(defaultHomeDir, cookieFilePrefix, defaultHost)
	defaultIdentityFile   = filePath(defaultHomeDir, identityFilePrefix, defaultHost)
	defaultCSRFFile       = filePath(defaultHomeDir, csrfFilePrefix, defaultHost)
	dcrwalletHomeDir      = dcrutil.AppDataDir("dcrwallet", false)
	defaultWalletCertFile = filepath.Join(dcrwalletHomeDir, "rpc.cert")
)

type Config struct {
	HomeDir     string `long:"appdata" description:"Path to application home directory"`
	Host        string `long:"host" description:"politeiawww host"`
	RawJSON     bool   `short:"j" long:"json" description:"Print raw JSON output"`
	ShowVersion bool   `short:"V" long:"version" description:"Display version information and exit"`
	Verbose     bool   `short:"v" long:"verbose" description:"Print verbose output"`

	Version string // cli version

	WalletHost string // Wallet host
	WalletCert string // Wallet GRPC certificate
	FaucetHost string // Testnet faucet host
	CSRF       string // CSRF header token

	Identity *identity.FullIdentity // User identity
	Cookies  []*http.Cookie         // User cookies

	csrfFile     string // CSRF file path
	cookieFile   string // Cookie file path
	identityFile string // User identity file path
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
// The above results in politeiawwwcli functioning properly without any config
// settings while still allowing the user to override settings with config
// files and command line options. Command line options always take precedence.
func Load() (*Config, error) {
	// Default config
	cfg := Config{
		HomeDir:    defaultHomeDir,
		Host:       defaultHost,
		WalletHost: defaultWalletHost + ":" + defaultWalletTestnetPort,
		WalletCert: defaultWalletCertFile,
		FaucetHost: defaultFaucetHost,
		Version:    version.String(),
	}

	// Pre-parse the command line options to see if an alternative config
	// file was specified.  The help message flag can be ignored since it
	// will be caught when we parse for the command to execute.
	var opts flags.Options = flags.PassDoubleDash | flags.IgnoreUnknown |
		flags.PrintErrors
	parser := flags.NewParser(&cfg, opts)
	_, err := parser.Parse()
	if err != nil {
		return nil, fmt.Errorf("parsing CLI options: %v", err)
	}

	// Show the version and exit if the version flag was specified.
	appName := filepath.Base(os.Args[0])
	appName = strings.TrimSuffix(appName, filepath.Ext(appName))
	if cfg.ShowVersion {
		fmt.Printf("%s version %s (Go version %s %s/%s)\n", appName,
			version.String(), runtime.Version(), runtime.GOOS,
			runtime.GOARCH)
		os.Exit(0)
	}

	// Update the application home directory if specified
	if cfg.HomeDir != defaultHomeDir {
		homeDir, err := filepath.Abs(cleanAndExpandPath(cfg.HomeDir))
		if err != nil {
			return nil, fmt.Errorf("cleaning path: %v", err)
		}
		cfg.HomeDir = homeDir
	}

	// Load options from config file.  Ignore errors caused by
	// the config file not existing.
	cfgFile := filepath.Join(cfg.HomeDir, defaultConfigFilename)
	cfgParser := flags.NewParser(&cfg, flags.Default)
	err = flags.NewIniParser(cfgParser).ParseFile(cfgFile)
	if err != nil {
		_, ok := err.(*os.PathError)
		if !ok {
			return nil, fmt.Errorf("parsing config file: %v\n", err)
		}
	}

	// Parse command line options again to ensure they take
	// precedence
	_, err = parser.Parse()
	if err != nil {
		return nil, fmt.Errorf("parsing CLI options: %v", err)
	}

	// Create home directory if it doesn't already exist
	err = os.MkdirAll(cfg.HomeDir, 0700)
	if err != nil {
		return nil, fmt.Errorf("MkdirAll %v:  %v", cfg.HomeDir, err)
	}

	// Validate host
	if !strings.HasPrefix(cfg.Host, "http://") &&
		!strings.HasPrefix(cfg.Host, "https://") {
		return nil, fmt.Errorf("host must begin with http:// or https://")
	}

	// Set user data file paths
	cfg.cookieFile = filePath(cfg.HomeDir, cookieFilePrefix, cfg.Host)
	cfg.csrfFile = filePath(cfg.HomeDir, csrfFilePrefix, cfg.Host)
	cfg.identityFile = filePath(cfg.HomeDir, identityFilePrefix, cfg.Host)

	// Load cookies
	if fileExists(cfg.cookieFile) {
		err := cfg.loadCookies()
		if err != nil {
			return nil, fmt.Errorf("loadCookies: %v", err)
		}
	}

	// Load CSRF token
	if fileExists(cfg.csrfFile) {
		err := cfg.loadCSRF()
		if err != nil {
			return nil, fmt.Errorf("loadCSRF: %v", err)
		}
	}

	// Load user identity
	if fileExists(cfg.identityFile) {
		err := cfg.loadIdentity()
		if err != nil {
			return nil, fmt.Errorf("loadIdentity: %v", err)
		}
	}

	return &cfg, nil
}

func (cfg *Config) SaveCookies(cookies []*http.Cookie) error {
	ck, err := json.Marshal(cookies)
	if err != nil {
		return fmt.Errorf("marshalling cookies: %v", err)
	}

	err = ioutil.WriteFile(cfg.cookieFile, ck, 0600)
	if err != nil {
		return fmt.Errorf("writing cookie file %v: %v",
			cfg.cookieFile, err)
	}

	return nil
}

func (cfg *Config) SaveCSRF(csrf string) error {
	err := ioutil.WriteFile(cfg.csrfFile, []byte(csrf), 0600)
	if err != nil {
		return fmt.Errorf("writing CSRF file %v: %v", cfg.csrfFile, err)
	}

	return nil
}

func (cfg *Config) SaveIdentity(id *identity.FullIdentity) error {
	err := id.Save(cfg.identityFile)
	if err != nil {
		return fmt.Errorf("saving identity to %v: %v", cfg.identityFile, err)
	}

	return nil
}

func (cfg *Config) loadCookies() error {
	if !fileExists(cfg.cookieFile) {
		return fmt.Errorf("cookie file does not exist %v", cfg.cookieFile)
	}

	b, err := ioutil.ReadFile(cfg.cookieFile)
	if err != nil {
		return fmt.Errorf("reading cookie file %v: %v",
			cfg.cookieFile, err)
	}

	var ck []*http.Cookie
	err = json.Unmarshal(b, &ck)
	if err != nil {
		return fmt.Errorf("unmarshalling cookies: %v", err)
	}

	cfg.Cookies = ck
	return nil
}

func (cfg *Config) loadCSRF() error {
	if !fileExists(cfg.csrfFile) {
		return fmt.Errorf("CSRF file does not exist %v", cfg.csrfFile)
	}

	b, err := ioutil.ReadFile(cfg.csrfFile)
	if err != nil {
		return fmt.Errorf("reading CSRF file %v: %v", cfg.csrfFile, err)
	}

	cfg.CSRF = string(b)
	return nil
}

func (cfg *Config) loadIdentity() error {
	if !fileExists(cfg.identityFile) {
		return fmt.Errorf("identity file does not exist %v", cfg.identityFile)
	}

	id, err := identity.LoadFullIdentity(cfg.identityFile)
	if err != nil {
		return fmt.Errorf("loading full identity: %v", err)
	}

	cfg.Identity = id
	return nil
}

// cleanAndExpandPath expands environment variables and leading ~ in the passed
// path, cleans the result, and returns it.
func cleanAndExpandPath(path string) string {
	// Expand initial ~ to OS specific home directory
	if strings.HasPrefix(path, "~") {
		var homeDir string
		usr, err := user.Current()
		if err == nil {
			homeDir = usr.HomeDir
		} else {
			// Fallback to CWD
			homeDir = "."
		}

		path = strings.Replace(path, "~", homeDir, 1)
	}

	// NOTE: The os.ExpandEnv doesn't work with Windows-style %VARIABLE%,
	// but the variables can still be expanded via POSIX-style $VARIABLE.
	return filepath.Clean(os.ExpandEnv(path))
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

func filePath(homeDir, prefix, host string) string {
	h := fnv.New32a()
	h.Write([]byte(host))

	file := prefix + fmt.Sprint(h.Sum32()) + ".json"
	return filepath.Join(homeDir, file)
}
