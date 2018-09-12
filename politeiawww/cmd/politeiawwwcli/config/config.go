package config

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiawww/sharedconfig"
)

const (
	defaultHost       = "https://proposals.decred.org/api"
	defaultWalletHost = "https://127.0.0.1" // Only allow localhost for now
	FaucetURL         = "https://faucet.decred.org/requestfaucet"

	defaultWalletMainnetPort = "19110"
	defaultWalletTestnetPort = "19111"

	ErrorNoUserIdentity = "No user identity found. Use 'newuser --save' to " +
		"save a user identity to appDataDir."
	ErrorBeforeAfterFlags = "The 'before' and 'after' flags cannot be used at " +
		"the same time."
)

var (
	dcrwalletHomeDir      = dcrutil.AppDataDir("dcrwallet", false)
	defaultHomeDir        = filepath.Join(sharedconfig.DefaultHomeDir, "cli")
	defaultWalletCertFile = filepath.Join(dcrwalletHomeDir, "rpc.cert")

	Host       = defaultHost
	HomeDir    = defaultHomeDir
	WalletCert = defaultWalletCertFile
	// only allow testnet wallet host for now
	WalletHost = defaultWalletHost + ":" + defaultWalletTestnetPort

	Cookies          []*http.Cookie
	CsrfToken        string
	UserIdentity     *identity.FullIdentity
	UserIdentityFile string

	cookieFile string
	csrfFile   string

	PrintJSON bool
	Verbose   bool
)

func stringToHash(s string) string {
	h := fnv.New32a()
	h.Write([]byte(s))
	return fmt.Sprint(h.Sum32())
}

// create a user identity filename that is unique for each host.  This makes
// it possible to interact with multiple hosts simultaneously.
func setUserIdentityFile(host string) {
	userIdentityFilename := "identity_" + stringToHash(host) + ".json"
	UserIdentityFile = filepath.Join(HomeDir, userIdentityFilename)
}

// create a user identity filename that is unique for each host.  This makes
// it possible to interact with multiple hosts simultaneously.
func setCookieFile(host string) {
	cookieFilename := "cookie_" + stringToHash(host) + ".json"
	cookieFile = filepath.Join(HomeDir, cookieFilename)
}

// create a csrf token filename that is unique for each host.   This makes
// it possible to interact with multiple hosts simultaneously.
func setCsrfFile(host string) {
	csrfFilename := "csrf_" + stringToHash(host) + ".json"
	csrfFile = filepath.Join(HomeDir, csrfFilename)
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

// load user identity from homeDir
func loadUserIdentity(path string) (*identity.FullIdentity, error) {
	id, err := identity.LoadFullIdentity(path)
	if err != nil {
		return nil, err
	}

	return id, nil
}

func Load() error {
	// create home directory if it doesn't already exist
	err := os.MkdirAll(HomeDir, 0700)
	if err != nil {
		return err
	}

	// load user identity
	setUserIdentityFile(Host)
	if fileExists(UserIdentityFile) {
		UserIdentity, err = loadUserIdentity(UserIdentityFile)
		if err != nil {
			return err
		}
	}

	// load cookies
	setCookieFile(Host)
	if fileExists(cookieFile) {
		Cookies, err = LoadCookies()
		if err != nil {
			return err
		}
	}

	// load CSRF token
	setCsrfFile(Host)
	if fileExists(csrfFile) {
		CsrfToken, err = loadCsrf()
		if err != nil {
			return err
		}
	}

	return nil
}

func SetHost(h string) error {
	if !strings.HasPrefix(h, "http://") && !strings.HasPrefix(h, "https://") {
		return fmt.Errorf("Host must begin with http:// or https://")
	}
	Host = h
	err := Load()
	return err
}

func SaveCookies(cookies []*http.Cookie) error {
	ck, err := json.Marshal(cookies)
	if err != nil {
		return fmt.Errorf("could not marshal cookies")
	}

	err = ioutil.WriteFile(cookieFile, ck, 0600)
	if err != nil {
		return err
	}

	if Verbose {
		fmt.Printf("Cookies saved to: %v\n", cookieFile)
	}

	return nil
}

func LoadCookies() ([]*http.Cookie, error) {
	b, err := ioutil.ReadFile(cookieFile)
	if err != nil {
		return nil, err
	}

	ck := []*http.Cookie{}
	err = json.Unmarshal(b, &ck)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal cookies")
	}

	return ck, nil
}

func SaveCsrf(csrf string) error {
	err := ioutil.WriteFile(csrfFile, []byte(csrf), 0600)
	if err != nil {
		return err
	}

	if Verbose {
		fmt.Printf("CSRF token saved to: %v\n", csrfFile)
	}

	return nil
}

func loadCsrf() (string, error) {
	b, err := ioutil.ReadFile(csrfFile)
	if err != nil {
		return "", err
	}

	return string(b), nil
}
