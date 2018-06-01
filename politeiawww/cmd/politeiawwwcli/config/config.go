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
	"strings"

	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiawww/sharedconfig"
)

const (
	ErrorNoUserIdentity = "No user idenitity found. Use 'newuser --save' to " +
		"save a user identity to appDataDir."
	ErrorBeforeAfterFlags = "The 'before' and 'after' flags cannot be used at " +
		"the same time."
)

var (
	defaultHost    = "https://127.0.0.1:4443"
	defaultHomeDir = filepath.Join(sharedconfig.DefaultHomeDir, "cli")
	FaucetURL      = "https://faucet.decred.org/requestfaucet"
	Host           = defaultHost
	HomeDir        = cleanAndExpandPath(defaultHomeDir)

	cookieFile       string
	csrfFile         string
	CsrfToken        string
	PrintJson        bool
	UserIdentityFile string
	UserIdentity     *identity.FullIdentity
	Cookies          []*http.Cookie
)

func stringToHash(s string) string {
	h := fnv.New32a()
	h.Write([]byte(s))
	return fmt.Sprint(h.Sum32())
}

func setHost(h string) error {
	if !strings.HasPrefix(h, "http://") && !strings.HasPrefix(h, "https://") {
		return fmt.Errorf("Host must begin with http:// or https://")
	}

	Host = cleanAndExpandPath(h)
	return nil
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

// cleanAndExpandPath expands environment variables and leading ~ in the
// passed path, cleans the result, and returns it.
func cleanAndExpandPath(path string) string {
	// Expand initial ~ to OS specific home directory.
	if strings.HasPrefix(path, "~") {
		usr, _ := user.Current()
		path = strings.Replace(path, "~", usr.HomeDir, 1)
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

func UpdateHost(host string) error {
	err := setHost(host)
	if err != nil {
		return err
	}

	setUserIdentityFile(host)
	setCookieFile(host)
	return nil
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
	fmt.Printf("Cookies saved to: %v\n", cookieFile)
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
	fmt.Printf("CSRF token saved to: %v\n", csrfFile)
	return nil
}

func loadCsrf() (string, error) {
	b, err := ioutil.ReadFile(csrfFile)
	if err != nil {
		return "", err
	}

	return string(b), nil
}
