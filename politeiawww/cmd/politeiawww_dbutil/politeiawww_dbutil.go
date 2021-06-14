// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"

	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/politeia/decredplugin"
	"github.com/decred/politeia/politeiad/backend/gitbe"
	"github.com/decred/politeia/politeiawww/config"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/politeiawww/user/cockroachdb"
	"github.com/decred/politeia/politeiawww/user/localdb"
	"github.com/decred/politeia/util"
	"github.com/jessevdk/go-flags"
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

const (
	defaultHost           = "localhost:26257"
	defaultRootCert       = "~/.cockroachdb/certs/clients/politeiawww/ca.crt"
	defaultClientCert     = "~/.cockroachdb/certs/clients/politeiawww/client.politeiawww.crt"
	defaultClientKey      = "~/.cockroachdb/certs/clients/politeiawww/client.politeiawww.key"
	defaultConfigFilename = "politeiawww_dbutil.conf"

	// Politeia repo info
	commentsJournalFilename = "comments.journal"

	// Journal actions
	journalActionAdd = "add" // Add entry
	journalActionDel = "del" // Delete entry
)

var (
	defaultHomeDir       = config.DefaultHomeDir
	defaultDataDir       = config.DefaultDataDir
	defaultEncryptionKey = filepath.Join(defaultHomeDir, "sbox.key")

	network string // Mainnet or testnet3
	userDB  user.Database
	cfg     Config
)

// Config describes the application options for dbutil
type Config struct {
	Database      string `long:"database" description:"cockroachdb or leveldb"`
	Testnet       bool   `long:"testnet" description:"use testnet database"`
	ClientCert    string `long:"clientcert" description:"file containing the CockroachDB SSL client cert (default ~/.cockroachdb/certs/clients/politeiawww/client.politeiawww.crt)"`
	ClientKey     string `long:"clientkey" description:"file containing the CockroachDB SSL client cert key (default ~/.cockroachdb/certs/clients/politeiawww/client.politeiawww.key)"`
	Datadir       string `long:"datadir" description:"politeiawww data directory (default osDataDir/politeiawww/data)"`
	EncryptionKey string `long:"encryptionkey" description:"file containing the CockroachDB encryption key (default osDataDir/politeiawww/sbox.key)"`
	Host          string `long:"host" description:"cockroachdb ip:port (default localhost:26257)"`
	RootCert      string `long:"rootcert" description:"file containing the CockroachDB SSL root cert (default ~/.cockroachdb/certs/clients/politeiawww/ca.crt)"`
	HomeDir       string `long:"appdata" description:"Path to application home directory"`
}

type dbutil struct {
	Config           Config
	AddCredits       AddCreditsCmd       `command:"addcredits" description:"add proposal credits to a user account"`
	CreateKey        CreateKeyCmd        `command:"createkey" description:"create a new encryption key that can be used to encrypt data at rest"`
	Dump             DumpCmd             `command:"dump" description:"dump the entire database or the contents of a specific user"`
	Help             HelpCmd             `command:"help" description:"print a detailed help message for a specific command"`
	Migrate          MigrateCmd          `command:"migrate" description:"migrate a leveldb user database to cockroachdb"`
	ResetTotp        ResetTotpCmd        `command:"resettotp" description:"reset a user's totp settings"`
	SetAdmin         SetAdminCmd         `command:"setadmin" description:"set the admin flag for a user"`
	SetEmail         SetEmailCmd         `command:"setemail" description:"set an user's email to the provided email address"`
	StubUsers        StubUsersCmd        `command:"stubusers" description:"create user stubs for the public keys in a politeia repo"`
	VerifyIdentities VerifyIdentitiesCmd `command:"verifyidentities" description:"verify a user's identities do not violate any politeia rules"`
}

func replayCommentsJournal(path string, pubkeys map[string]struct{}) error {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(b))

	for {
		var action gitbe.JournalAction
		err = d.Decode(&action)
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return fmt.Errorf("journal action: %v", err)
		}

		switch action.Action {
		case journalActionAdd:
			var c decredplugin.Comment
			err = d.Decode(&c)
			if err != nil {
				return fmt.Errorf("journal add: %v", err)
			}
			pubkeys[c.PublicKey] = struct{}{}

		case journalActionDel:
			var cc decredplugin.CensorComment
			err = d.Decode(&cc)
			if err != nil {
				return fmt.Errorf("journal censor: %v", err)
			}
			pubkeys[cc.PublicKey] = struct{}{}

		default:
			return fmt.Errorf("invalid action: %v",
				action.Action)
		}
	}

	return nil
}

func validateCockroachParams() error {
	// Validate host
	_, err := url.Parse(cfg.Host)
	if err != nil {
		return fmt.Errorf("parse host '%v': %v",
			cfg.Host, err)
	}

	// Validate root cert
	b, err := ioutil.ReadFile(cfg.RootCert)
	if err != nil {
		return fmt.Errorf("read rootcert: %v", err)
	}

	block, _ := pem.Decode(b)
	_, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse rootcert: %v", err)
	}

	// Validate client key pair
	_, err = tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
	if err != nil {
		return fmt.Errorf("load key pair clientcert and "+
			"clientkey: %v", err)
	}

	// Ensure encryption key file exists, if not, create a new one
	if !util.FileExists(cfg.EncryptionKey) {
		return fmt.Errorf("file not found %v", cfg.EncryptionKey)
	}

	return nil
}

func connectToDatabase() error {
	switch cfg.Database {
	case "leveldb":
		dbDir := filepath.Join(cfg.Datadir, network)
		fmt.Printf("Database: %v\n", dbDir)

		_, err := os.Stat(dbDir)
		if err != nil {
			if os.IsNotExist(err) {
				err = fmt.Errorf("leveldb dir not found: %v", dbDir)
			}
			return err
		}
		ldb, err := localdb.New(dbDir)
		if err != nil {
			return err
		}
		userDB = ldb
		return nil

	case "cockroachdb":
		err := validateCockroachParams()
		if err != nil {
			return err
		}
		db, err := cockroachdb.New(cfg.Host, network, cfg.RootCert,
			cfg.ClientCert, cfg.ClientKey, cfg.EncryptionKey)
		if err != nil {
			return fmt.Errorf("new cockroachdb: %v", err)
		}
		userDB = db
		return nil
	default:
		return fmt.Errorf("the command needs a DB connection. " +
			"Please use the --database=<name> flag")
	}
}

func _main() error {
	// load config options
	cfg = Config{
		Testnet:       false,
		Datadir:       util.CleanAndExpandPath(defaultDataDir),
		Host:          util.CleanAndExpandPath(defaultHost),
		RootCert:      util.CleanAndExpandPath(defaultRootCert),
		ClientCert:    util.CleanAndExpandPath(defaultClientCert),
		ClientKey:     util.CleanAndExpandPath(defaultClientKey),
		EncryptionKey: util.CleanAndExpandPath(defaultEncryptionKey),
		HomeDir:       util.CleanAndExpandPath(defaultHomeDir),
	}
	var opts flags.Options = flags.PassDoubleDash | flags.IgnoreUnknown | flags.PrintErrors
	par := flags.NewParser(&cfg, opts)
	_, err := par.Parse()
	if err != nil {
		return fmt.Errorf("parsing CLI options: %v", err)
	}

	// Load options from config file
	cfgFile := filepath.Join(cfg.HomeDir, defaultConfigFilename)
	cfgParser := flags.NewParser(&cfg, flags.Default)
	err = flags.NewIniParser(cfgParser).ParseFile(cfgFile)
	if err != nil {
		var e *os.PathError
		if errors.As(err, &e) {
			fmt.Printf("Warning: no config file found at %v. Using default values.\n", cfgFile)
		} else {
			return fmt.Errorf("parsing config file: %v", err)
		}
	}

	// Parse command line options again to ensure they take precedence
	_, err = par.Parse()
	if err != nil {
		return fmt.Errorf("parsing CLI options: %v", err)
	}

	// network checking
	if cfg.Testnet {
		network = chaincfg.TestNet3Params().Name
	} else {
		network = chaincfg.MainNetParams().Name
	}

	var cli dbutil
	var parser = flags.NewParser(&cli, flags.Default)
	if _, err := parser.Parse(); err != nil {
		flagsErr, ok := err.(*flags.Error)
		if ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		} else {
			os.Exit(1)
		}
	}

	return nil
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
