package config

import (
	"fmt"
	"hash/fnv"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"

	flags "github.com/btcsuite/go-flags"
	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/politeia/politeiawww/database"
	"github.com/decred/politeia/politeiawww/sharedconfig"
	"github.com/decred/politeia/util"
	"github.com/decred/politeia/util/version"
)

const (
	defaultHomeDirname    = "dbutil"
	defaultDataDirName    = "data"
	defaultConfigFilename = "politeiawww_dbutil.conf"

	LevelDBOption     = "leveldb"
	CockroachDBOption = "cockroachdb"
)

var (
	defaultHomeDir    = filepath.Join(sharedconfig.DefaultHomeDir, defaultHomeDirname)
	defaultDataDir    = filepath.Join(sharedconfig.DefaultHomeDir, defaultDataDirName)
	defaultConfigFile = filepath.Join(defaultHomeDir, defaultConfigFilename)
)

type Config struct {
	HomeDir       string `long:"appdata" description:"Path to application home directory"`
	TestNet       bool   `long:"testnet" description:"Use the test network"`
	Database      string `long:"database" description:"Database to be used. Valid options are {cockroachdb, leveldb}"`
	DataDir       string `long:"datadir" description:"Directory where the database is stored"`
	DBKeyFilename string `long:"dbkeyfilename" description:"File containing the secret key for the database"`
	DBHost        string `long:"dbhost" description:"Database ip:port"`
	DBCertDir     string `long:"dbcertdir" description:"Directory containing SSL client certificates"`
	DBRootCert    string `long:"dbrootcert" description:"File containing SSL root certificate"`
	EncryptDB     bool   `long:"encryptdb" description:"If true the database will encrypt/decrypt for saving and retrieving records"`
	RawJSON       bool   `short:"j" long:"json" description:"Print raw JSON output"`
	ShowVersion   bool   `short:"V" long:"version" description:"Display version information and exit"`
	Verbose       bool   `short:"v" long:"verbose" description:"Print verbose output"`

	DBKey   *database.EncryptionKey
	Net     string // // Which net is being used (mainnet/testnet)
	Version string // cli version
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
		HomeDir:  defaultHomeDir,
		DataDir:  defaultDataDir,
		Database: LevelDBOption,
		Version:  version.String(),
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

	// load database encryption key
	err = loadDBKey(&cfg)
	if err != nil {
		return nil, fmt.Errorf("loadDBKey %v: %v", cfg.DBKeyFilename, err)
	}

	// Set net value.
	if cfg.TestNet {
		cfg.Net = chaincfg.TestNet3Params.Name
	} else {
		cfg.Net = chaincfg.MainNetParams.Name
	}

	// Append the network type to the data directory so it is "namespaced"
	// per network.
	cfg.DataDir = cleanAndExpandPath(cfg.DataDir)
	cfg.DataDir = filepath.Join(cfg.DataDir, cfg.Net)

	// // Set user data file paths
	// cfg.cookieFile = filePath(cfg.HomeDir, cookieFilePrefix, cfg.Host)

	// // Load cookies
	// if fileExists(cfg.cookieFile) {
	// 	err := cfg.loadCookies()
	// 	if err != nil {
	// 		return nil, fmt.Errorf("loadCookies: %v", err)
	// 	}
	// }

	return &cfg, nil
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

// loadDbKey tries to load the database encription key. If it cannot find a
// key it will prompt instructions on how to generate a new one.
func loadDBKey(cfg *Config) error {
	if !cfg.EncryptDB {
		// Do not try to load the db key if the encryption
		// is disabled.
		return nil
	}
	// Setup the key path.
	if cfg.DBKeyFilename == "" {
		return fmt.Errorf("dbkeyfilename cannot be blank")
	}
	cfg.DBKeyFilename = cleanAndExpandPath(cfg.DBKeyFilename)

	// Check if the key file exists.
	if !util.FileExists(cfg.DBKeyFilename) {
		return fmt.Errorf("You must specify a valid database key or create " +
			"a new one by running polteiawww --createdbkey flag")
	}

	// Load the DB key
	ek, err := database.LoadEncryptionKey(cfg.DBKeyFilename)
	if err != nil {
		return err
	}
	cfg.DBKey = ek

	return nil
}
