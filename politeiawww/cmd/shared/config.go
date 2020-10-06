// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package shared

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/decred/dcrd/dcrutil/v3"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/util/version"
	flags "github.com/jessevdk/go-flags"
)

const (
	defaultHost              = "https://proposals.decred.org/api"
	defaultFaucetHost        = "https://faucet.decred.org/requestfaucet"
	defaultWalletHost        = "127.0.0.1"
	defaultWalletTestnetPort = "19111"

	userFile     = "user.txt"
	csrfFile     = "csrf.txt"
	cookieFile   = "cookies.json"
	identityFile = "identity.json"
)

var (
	dcrwalletHomeDir      = dcrutil.AppDataDir("dcrwallet", false)
	defaultWalletCertFile = filepath.Join(dcrwalletHomeDir, "rpc.cert")
)

// Config represents the piwww configuration settings.
type Config struct {
	HomeDir     string `long:"appdata" description:"Path to application home directory"`
	Host        string `long:"host" description:"politeiawww host"`
	RawJSON     bool   `short:"j" long:"json" description:"Print raw JSON output"`
	ShowVersion bool   `long:"version" description:"Display version information and exit"`
	SkipVerify  bool   `long:"skipverify" description:"Skip verifying the server's certifcate chain and host name"`
	Verbose     bool   `short:"v" long:"verbose" description:"Print verbose output"`
	Silent      bool   `long:"silent" description:"Suppress all output"`

	DataDir    string // Application data dir
	Version    string // CLI version
	WalletHost string // Wallet host
	WalletCert string // Wallet GRPC certificate
	FaucetHost string // Testnet faucet host
	CSRF       string // CSRF header token

	Identity *identity.FullIdentity // User identity
	Cookies  []*http.Cookie         // User cookies
}

// LoadConfig initializes and parses the config using a config file and command
// line options.
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
func LoadConfig(homeDir, dataDirname, configFilename string) (*Config, error) {
	// Default config
	cfg := Config{
		HomeDir:    homeDir,
		DataDir:    filepath.Join(homeDir, dataDirname),
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
	if cfg.HomeDir != homeDir {
		homeDir, err := filepath.Abs(cleanAndExpandPath(cfg.HomeDir))
		if err != nil {
			return nil, fmt.Errorf("cleaning path: %v", err)
		}
		cfg.HomeDir = homeDir
		cfg.DataDir = filepath.Join(cfg.HomeDir, dataDirname)
	}

	// Load options from config file.  Ignore errors caused by
	// the config file not existing.
	cfgFile := filepath.Join(cfg.HomeDir, configFilename)
	cfgParser := flags.NewParser(&cfg, flags.Default)
	err = flags.NewIniParser(cfgParser).ParseFile(cfgFile)
	if err != nil {
		var e *os.PathError
		if errors.As(err, &e) {
			fmt.Printf("Warning: no config file found at %v\n", cfgFile)
		} else {
			return nil, fmt.Errorf("parsing config file: %v", err)
		}
	}

	// Parse command line options again to ensure they take
	// precedence
	_, err = parser.Parse()
	if err != nil {
		return nil, fmt.Errorf("parsing CLI options: %v", err)
	}

	// Create home and data directories if they doesn't already
	// exist
	err = os.MkdirAll(cfg.HomeDir, 0700)
	if err != nil {
		return nil, fmt.Errorf("MkdirAll %v:  %v", cfg.HomeDir, err)
	}
	err = os.MkdirAll(cfg.DataDir, 0700)
	if err != nil {
		return nil, fmt.Errorf("MkdirAll %v:  %v", cfg.DataDir, err)
	}

	// Validate host
	u, err := url.Parse(cfg.Host)
	if err != nil {
		return nil, fmt.Errorf("parse host: %v", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("host scheme must be http or https")
	}

	// Load cookies
	cookies, err := cfg.loadCookies()
	if err != nil {
		return nil, fmt.Errorf("loadCookies: %v", err)
	}
	cfg.Cookies = cookies

	// Load CSRF tokens
	csrf, err := cfg.loadCSRF()
	if err != nil {
		return nil, fmt.Errorf("loadCSRF: %v", err)
	}
	cfg.CSRF = csrf

	// Load identity for the logged in user
	username, err := cfg.loadLoggedInUsername()
	if err != nil {
		return nil, fmt.Errorf("load username: %v", err)
	}
	id, err := cfg.LoadIdentity(username)
	if err != nil {
		return nil, fmt.Errorf("load identity: %v", err)
	}
	cfg.Identity = id

	return &cfg, nil
}

// hostFilePath returns the host specific file path for the passed in file.
// This means that the hostname is prepended to the filename.  politeiawwwcli
// data is segmented by host so that we can interact with multiple hosts
// simultaneously.
func (cfg *Config) hostFilePath(filename string) (string, error) {
	u, err := url.Parse(cfg.Host)
	if err != nil {
		return "", fmt.Errorf("parse host: %v", err)
	}

	f := fmt.Sprintf("%v_%v", u.Hostname(), filename)
	return filepath.Join(cfg.DataDir, f), nil
}

func (cfg *Config) loadCookies() ([]*http.Cookie, error) {
	f, err := cfg.hostFilePath(cookieFile)
	if err != nil {
		return nil, fmt.Errorf("hostFilePath: %v", err)
	}

	if !fileExists(f) {
		// Nothing to load
		return nil, nil
	}

	b, err := ioutil.ReadFile(f)
	if err != nil {
		return nil, fmt.Errorf("read file %v: %v", f, err)
	}

	var c []*http.Cookie
	err = json.Unmarshal(b, &c)
	if err != nil {
		return nil, fmt.Errorf("unmarshal cookies: %v", err)
	}

	return c, nil
}

// SaveCookies writes the passed in cookies to the host specific cookie file.
func (cfg *Config) SaveCookies(cookies []*http.Cookie) error {
	b, err := json.Marshal(cookies)
	if err != nil {
		return fmt.Errorf("marshal cookies: %v", err)
	}

	f, err := cfg.hostFilePath(cookieFile)
	if err != nil {
		return fmt.Errorf("hostFilePath: %v", err)
	}

	err = ioutil.WriteFile(f, b, 0600)
	if err != nil {
		return fmt.Errorf("write file %v: %v", f, err)
	}

	cfg.Cookies = cookies
	return nil
}

func (cfg *Config) loadCSRF() (string, error) {
	f, err := cfg.hostFilePath(csrfFile)
	if err != nil {
		return "", fmt.Errorf("hostFilePath: %v", err)
	}

	if !fileExists(f) {
		// Nothing to load
		return "", nil
	}

	b, err := ioutil.ReadFile(f)
	if err != nil {
		return "", fmt.Errorf("read file %v: %v", f, err)
	}

	return string(b), nil
}

// SaveCSRF writes the passed in CSRF token to the host specific CSRF file.
func (cfg *Config) SaveCSRF(csrf string) error {
	f, err := cfg.hostFilePath(csrfFile)
	if err != nil {
		return fmt.Errorf("hostFilePath: %v", err)
	}

	err = ioutil.WriteFile(f, []byte(csrf), 0600)
	if err != nil {
		return fmt.Errorf("write file %v: %v", f, err)
	}

	cfg.CSRF = csrf
	return nil
}

// identityFilePath returns the file path for a specific user identity.  We
// store identities in a user specific file so that we can keep track of the
// identities of multiple users.
func (cfg *Config) identityFilePath(username string) (string, error) {
	return cfg.hostFilePath(fmt.Sprintf("%v_%v", username, identityFile))
}

func (cfg *Config) LoadIdentity(username string) (*identity.FullIdentity, error) {
	if username == "" {
		// No logged in user
		return nil, nil
	}

	f, err := cfg.identityFilePath(username)
	if err != nil {
		return nil, fmt.Errorf("identityFilePath: %v", err)
	}

	if !fileExists(f) {
		// User identity doesn't exist
		return nil, nil
	}

	id, err := identity.LoadFullIdentity(f)
	if err != nil {
		return nil, fmt.Errorf("load identity %v: %v", f, err)
	}

	return id, nil
}

// SaveIdentity writes the passed in user identity to disk so that it can be
// persisted between commands.  The prepend the hostname and the username onto
// the idenity filename so that we can keep track of the identities for
// multiple users per host.
func (cfg *Config) SaveIdentity(user string, id *identity.FullIdentity) error {
	f, err := cfg.identityFilePath(user)
	if err != nil {
		return fmt.Errorf("identityFilePath: %v", err)
	}

	err = id.Save(f)
	if err != nil {
		return fmt.Errorf("save idenity to %v: %v", f, err)
	}

	cfg.Identity = id
	return nil
}

func (cfg *Config) loadLoggedInUsername() (string, error) {
	f, err := cfg.hostFilePath(userFile)
	if err != nil {
		return "", fmt.Errorf("hostFilePath: %v", err)
	}

	if !fileExists(f) {
		// Nothing to load
		return "", nil
	}

	b, err := ioutil.ReadFile(f)
	if err != nil {
		return "", fmt.Errorf("read file %v: %v", f, err)
	}

	return string(b), nil
}

// SaveLoggedInUsername saved the passed in username to the on-disk user file.
// We persist the logged in username between commands so that we know which
// identity to load.
func (cfg *Config) SaveLoggedInUsername(username string) error {
	f, err := cfg.hostFilePath(userFile)
	if err != nil {
		return fmt.Errorf("hostFilePath: %v", err)
	}

	err = ioutil.WriteFile(f, []byte(username), 0600)
	if err != nil {
		return fmt.Errorf("write file %v: %v", f, err)
	}

	// The config identity is the identity of the logged in
	// user so we need to update the identity when the logged
	// in user changes.
	id, err := cfg.LoadIdentity(username)
	if err != nil {
		return fmt.Errorf("load identity: %v", err)
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
