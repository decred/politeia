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
	"path/filepath"
	"time"

	"github.com/decred/dcrd/hdkeychain/v3"
	"github.com/decred/politeia/util"
)

const (
	// Currently available modes to run politeia, by default piwww, is used.
	PiWWWMode  = "piwww"
	CMSWWWMode = "cmswww"

	defaultDcrdataMainnet = "dcrdata.decred.org:443"
	defaultDcrdataTestnet = "testnet.decred.org:443"

	defaultPaywallMinConfirmations = uint64(2)
	defaultPaywallAmount           = uint64(0)

	defaultMailAddressCMS = "Contractor Management System <noreply@example.org>"
	defaultMailRateLimit  = 100 // Email limit per user

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
	// Default start date to start pulling code statistics if none specified.
	// 6 months in minutes 60min * 24h * 7days * 26 weeks
	defaultCodeStatStart = time.Now().Add(-1 * time.Minute * 60 * 24 * 7 * 26)

	// Default end date to stop pull code statistics if none specified.
	// Use today as the default end code stat date.
	defaultCodeStatEnd = time.Now()

	// Check to make sure code stat start time is sane 2 years from today.
	// 2 years in minutes 60min * 24h * 7days * 52weeks * 2years
	codeStatCheck = time.Now().Add(-1 * time.Minute * 60 * 24 * 7 * 52 * 2)
)

// LegacyConfig represents the config options for legacy API.
//
// Everything in this config is DEPRECATED and will be removed in the near
// future.
type LegacyConfig struct {
	// Legacy user database settings
	DBRootCert       string `long:"dbrootcert" description:"File containing the CA certificate for the database"`
	DBCert           string `long:"dbcert" description:"File containing the politeiawww client certificate for the database"`
	DBKey            string `long:"dbkey" description:"File containing the politeiawww client certificate key for the database"`
	EncryptionKey    string `long:"encryptionkey" description:"File containing encryption key used for encrypting user data at rest"`
	OldEncryptionKey string `long:"oldencryptionkey" description:"File containing old encryption key (only set when rotating keys)"`

	// Settings the need to be turned into plugin settings.
	MailRateLimit    int    `long:"mailratelimit" description:"Limits the amount of emails a user can receive in 24h"`
	WebServerAddress string `long:"webserveraddress" description:"Web server address used to create email links (format: <scheme>://<host>[:<port>])"`

	// Legacy API settings
	Mode        string `long:"mode" description:"Mode www runs as. Supported values: piwww, cmswww"`
	DcrdataHost string `long:"dcrdatahost" description:"Dcrdata ip:port"`

	// Legacy pi settings
	PaywallAmount            uint64 `long:"paywallamount" description:"Amount of DCR (in atoms) required for a user to register or submit a proposal."`
	PaywallXpub              string `long:"paywallxpub" description:"Extended public key for deriving paywall addresses."`
	MinConfirmationsRequired uint64 `long:"minconfirmations" description:"Minimum blocks confirmation for accepting paywall as paid. Only works in TestNet."`

	// Legacy cmswww settings
	BuildCMSDB           bool     `long:"buildcmsdb" description:"Build the cmsdb from scratch"`
	GithubAPIToken       string   `long:"githubapitoken" description:"API Token used to communicate with github API.  When populated in cmswww mode, github-tracker is enabled."`
	CodeStatRepos        []string `long:"codestatrepos" description:"Org/Repositories to crawl for code statistics"`
	CodeStatOrganization string   `long:"codestatorg" description:"Organization to crawl for code statistics"`
	CodeStatStart        int64    `long:"codestatstart" description:"Date in which to look back to for code stat crawl (default 6 months back)"`
	CodeStatEnd          int64    `long:"codestatend" description:"Date in which to end look back to for code stat crawl (default today)"`
	CodeStatSkipSync     bool     `long:"codestatskipsync" description:"Skip pull request crawl on startup"`
	VoteDurationMin      uint32   `long:"votedurationmin" description:"Minimum duration of a dcc vote in blocks"`
	VoteDurationMax      uint32   `long:"votedurationmax" description:"Maximum duration of a dcc vote in blocks"`
}

// setupLegacyConfig sets up the legacy config settings.
func setupLegacyConfig(cfg *Config) error {
	// Setup mode specific settings
	switch cfg.Mode {
	case CMSWWWMode:
		// Setup CMS specific settings
		if cfg.MailAddress == defaultMailAddress {
			cfg.MailAddress = defaultMailAddressCMS
		}
		err := setupLegacyCMSSettings(cfg)
		if err != nil {
			return err
		}

	case PiWWWMode:
		// Setup pi specific settings
		err := setupLegacyPiSettings(cfg)
		if err != nil {
			return err
		}

	default:
		return fmt.Errorf("invalid mode '%v'", cfg.Mode)
	}

	// Verify the various config settings
	err := setupLegacyUserDBSettings(cfg)
	if err != nil {
		return err
	}

	// Verify the SMTP mail settings
	switch {
	case cfg.MailHost == "" && cfg.MailUser == "" &&
		cfg.MailPass == "" && cfg.WebServerAddress == "":
		// Email is disabled; this is ok
	case cfg.MailHost != "" && cfg.MailUser != "" &&
		cfg.MailPass != "" && cfg.WebServerAddress != "":
		// All mail settings have been set; this is ok
	default:
		return fmt.Errorf("either all or none of the following config" +
			"options should be supplied: mailhost, mailuser, mailpass, " +
			"webserveraddress")
	}

	// Verify the webserver address
	_, err = url.Parse(cfg.WebServerAddress)
	if err != nil {
		return fmt.Errorf("invalid webserveraddress setting '%v': %v",
			cfg.WebServerAddress, err)
	}

	// Verify the dcrdata host
	if cfg.DcrdataHost == "" {
		if cfg.TestNet {
			cfg.DcrdataHost = defaultDcrdataTestnet
		} else {
			cfg.DcrdataHost = defaultDcrdataMainnet
		}
	}
	_, err = url.Parse(cfg.DcrdataHost)
	if err != nil {
		return fmt.Errorf("invalid dcrdata setting '%v': %v",
			cfg.DcrdataHost, err)
	}

	return nil
}

// setupLegacyUserDBSettings sets up the legacy user database config settings.
func setupLegacyUserDBSettings(cfg *Config) error {
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
		// Verify database host
		if cfg.DBHost == "" {
			cfg.DBHost = defaultCockroachDBHost
		}
		_, err := url.Parse(cfg.DBHost)
		if err != nil {
			return fmt.Errorf("invalid dbhost '%v': %v",
				cfg.DBHost, err)
		}

		// Verify certs and encryption key. Cockroachdb requires
		// these settings.
		switch {
		case cfg.DBRootCert == "":
			return fmt.Errorf("dbrootcert param is required")
		case cfg.DBCert == "":
			return fmt.Errorf("dbcert param is required")
		case cfg.DBKey == "":
			return fmt.Errorf("dbkey param is required")
		}
		if cfg.EncryptionKey == "" {
			cfg.EncryptionKey = filepath.Join(cfg.HomeDir, "sbox.key")
		}

		// Clean file paths
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
		// Set defaults
		if cfg.EncryptionKey == "" {
			cfg.EncryptionKey = filepath.Join(cfg.HomeDir, "sbox.key")
		}

		// Clean encryption keys paths.
		cfg.EncryptionKey = util.CleanAndExpandPath(cfg.EncryptionKey)
		cfg.OldEncryptionKey = util.CleanAndExpandPath(cfg.OldEncryptionKey)

		// Validate user database encryption keys.
		err := validateEncryptionKeys(cfg.EncryptionKey, cfg.OldEncryptionKey)
		if err != nil {
			return err
		}
	}

	return nil
}

// setupLegacyPiSettings sets up the legacy piwww settings.
func setupLegacyPiSettings(cfg *Config) error {
	// Verify paywall settings
	paywallIsEnabled := cfg.PaywallAmount != 0 || cfg.PaywallXpub != ""
	if !paywallIsEnabled {
		return nil
	}

	// Parse extended public key
	_, err := hdkeychain.NewKeyFromString(cfg.PaywallXpub,
		cfg.ActiveNet.Params)
	if err != nil {
		return fmt.Errorf("invalid extended public key: %v", err)
	}

	// Verify paywall amount
	if cfg.PaywallAmount < dust {
		return fmt.Errorf("paywall amount needs to be higher than %v", dust)
	}

	// Verify required paywall confirmations
	if !cfg.TestNet &&
		cfg.MinConfirmationsRequired != defaultPaywallMinConfirmations {
		return fmt.Errorf("cannot set --minconfirmations on mainnet")
	}

	return nil
}

// setupLegacyCMSSettings sets up the legacy CMS config settings.
func setupLegacyCMSSettings(cfg *Config) error {
	if cfg.CodeStatStart > 0 &&
		(time.Unix(cfg.CodeStatStart, 0).Before(codeStatCheck) ||
			time.Unix(cfg.CodeStatStart, 0).After(time.Now())) {
		return fmt.Errorf("you have entered an invalid code stat start date")
	}
	if cfg.CodeStatEnd > 0 &&
		time.Unix(cfg.CodeStatEnd, 0).Before(time.Unix(cfg.CodeStatStart, 0)) {
		return fmt.Errorf("you have entered an invalid code stat end date")
	}
	if cfg.CodeStatStart <= 0 {
		cfg.CodeStatStart = defaultCodeStatStart.Unix()
	}
	if cfg.CodeStatEnd <= 0 {
		cfg.CodeStatEnd = defaultCodeStatEnd.Unix()
	}
	return nil
}

// validateEncryptionKeys validates the provided encryption keys.
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
