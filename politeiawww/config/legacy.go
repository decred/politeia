// Copyright (c) 2013-2014 The btcsuite developers
// Copyright (c) 2015-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package config

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/decred/dcrd/hdkeychain/v3"
	"github.com/decred/politeia/util"
)

const (
	// Currently available modes to run politeia, by default piwww, is
	// used.
	PoliteiaWWWMode = "piwww"
	CMSWWWMode      = "cmswww"

	defaultPaywallMinConfirmations = uint64(2)
	defaultPaywallAmount           = uint64(0)

	defaultMailAddressPi  = "Politeia <noreply@example.org>"
	defaultMailAddressCMS = "Contractor Management System <noreply@example.org>"
	defaultMailRateLimit  = 100 // Email limit per user

	defaultDcrdataMainnet = "dcrdata.decred.org:443"
	defaultDcrdataTestnet = "testnet.decred.org:443"

	defaultVoteDurationMin = uint32(2016)
	defaultVoteDurationMax = uint32(4032)

	// dust value can be found increasing the amount value until we get false
	// from IsDustAmount function. Amounts can not be lower than dust
	// func IsDustAmount(amount int64, relayFeePerKb int64) bool {
	//     totalSize := 8 + 2 + 1 + 25 + 165
	// 	   return int64(amount)*1000/(3*int64(totalSize)) < int64(relayFeePerKb)
	// }
	dust = 60300
)

var (
	defaultEncryptionKey = filepath.Join(defaultHomeDir, "sbox.key")

	// Default start date to start pulling code statistics if none specified.
	defaultCodeStatStart = time.Now().Add(-1 * time.Minute * 60 * 24 * 7 * 26) // 6 months in minutes 60min * 24h * 7days * 26 weeks

	// Default end date to stop pull code statistics if none specified.
	defaultCodeStatEnd = time.Now() // Use today as the default end code stat date

	// Check to make sure code stat start time is sane 2 years from today.
	codeStatCheck = time.Now().Add(-1 * time.Minute * 60 * 24 * 7 * 52 * 2) // 2 years in minutes 60min * 24h * 7days * 52weeks * 2years

)

type legacyConfig struct {
	// Legacy user database settings
	DBRootCert       string `long:"dbrootcert" description:"File containing the CA certificate for the database"`
	DBCert           string `long:"dbcert" description:"File containing the politeiawww client certificate for the database"`
	DBKey            string `long:"dbkey" description:"File containing the politeiawww client certificate key for the database"`
	EncryptionKey    string `long:"encryptionkey" description:"File containing encryption key used for encrypting user data at rest"`
	OldEncryptionKey string `long:"oldencryptionkey" description:"File containing old encryption key (only set when rotating keys)"`

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
}

func loadLegacyConfig(cfg *Config) error {
	lcfg := legacyConfig{
		Mode:                     PoliteiaWWWMode,
		PaywallAmount:            defaultPaywallAmount,
		MinConfirmationsRequired: defaultPaywallMinConfirmations,
		VoteDurationMin:          defaultVoteDurationMin,
		VoteDurationMax:          defaultVoteDurationMax,
		MailRateLimit:            defaultMailRateLimit,
	}
	_ = lcfg

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
		return err
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
			return fmt.Errorf("leveldb --encryptionkey not supported")
		case cfg.OldEncryptionKey != "":
			return fmt.Errorf("leveldb --oldencryptionkey not supported")
		}

	case CockroachDB:
		// Cockroachdb requires these settings.
		switch {
		case cfg.DBRootCert == "":
			return fmt.Errorf("dbrootcert param is required")
		case cfg.DBCert == "":
			return fmt.Errorf("dbcert param is required")
		case cfg.DBKey == "":
			return fmt.Errorf("dbkey param is required")
		}

		// Set default DBHost if not set.
		if cfg.DBHost == "" {
			cfg.DBHost = defaultCockroachDBHost
		}

		// Validate DB host.
		err := validateDBHost(cfg.DBHost)
		if err != nil {
			return err
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
			return fmt.Errorf("validate encryption keys: %v", err)
		}

		// Validate user database root cert
		b, err := ioutil.ReadFile(cfg.DBRootCert)
		if err != nil {
			return fmt.Errorf("read dbrootcert: %v", err)
		}
		block, _ := pem.Decode(b)
		_, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse dbrootcert: %v", err)
		}

		// Validate user database key pair
		_, err = tls.LoadX509KeyPair(cfg.DBCert, cfg.DBKey)
		if err != nil {
			return fmt.Errorf("load key pair dbcert "+
				"and dbkey: %v", err)
		}

	case MySQL:
		// The database password is provided in an env variable.
		cfg.DBPass = os.Getenv(envDBPass)
		if cfg.DBPass == "" {
			return fmt.Errorf("dbpass not found; you must provide " +
				"the database password for the politeiawww user in the env " +
				"variable DBPASS")
		}

		// Set default DBHost if not set.
		if cfg.DBHost == "" {
			cfg.DBHost = defaultMySQLDBHost
		}

		// Validate DB host.
		err := validateDBHost(cfg.DBHost)
		if err != nil {
			return err
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
			return fmt.Errorf("validate encryption keys: %v", err)
		}

	default:
		return fmt.Errorf("invalid userdb '%v'; must "+
			"be leveldb, cockroachdb or mysql", cfg.UserDB)
	}

	// Verify paywall settings
	paywallIsEnabled := cfg.PaywallAmount != 0 || cfg.PaywallXpub != ""
	if paywallIsEnabled {
		// Parse extended public key
		_, err := hdkeychain.NewKeyFromString(cfg.PaywallXpub,
			cfg.ActiveNet.Params)
		if err != nil {
			return fmt.Errorf("error processing extended "+
				"public key: %v", err)
		}

		// Verify paywall amount
		if cfg.PaywallAmount < dust {
			return fmt.Errorf("paywall amount needs to be "+
				"higher than %v", dust)
		}

		// Verify required paywall confirmations
		if !cfg.TestNet &&
			cfg.MinConfirmationsRequired != defaultPaywallMinConfirmations {
			return fmt.Errorf("cannot set --minconfirmations on mainnet")
		}
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
		return fmt.Errorf("either all or none of the " +
			"following config options should be supplied: " +
			"mailhost, mailuser, mailpass, webserveraddress")
	}

	u, err := url.Parse(cfg.WebServerAddress)
	if err != nil {
		return fmt.Errorf("unable to parse web server address: %v", err)
	}
	cfg.WebServerAddress = u.String()

	if cfg.CodeStatStart > 0 &&
		(time.Unix(cfg.CodeStatStart, 0).Before(codeStatCheck) ||
			time.Unix(cfg.CodeStatStart, 0).After(time.Now())) {
		return fmt.Errorf("you have entered an invalid code stat " +
			"start date")
	}

	if cfg.CodeStatEnd > 0 &&
		time.Unix(cfg.CodeStatEnd, 0).Before(time.Unix(cfg.CodeStatStart, 0)) {
		return fmt.Errorf("you have entered an invalid code stat " +
			"end date")
	}

	if cfg.CodeStatStart <= 0 {
		cfg.CodeStatStart = defaultCodeStatStart.Unix()
	}

	if cfg.CodeStatEnd <= 0 {
		cfg.CodeStatEnd = defaultCodeStatEnd.Unix()
	}

	// Setup dcrdata addresses
	if cfg.DcrdataHost == "" {
		if cfg.TestNet {
			cfg.DcrdataHost = defaultDcrdataTestnet
		} else {
			cfg.DcrdataHost = defaultDcrdataMainnet
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
