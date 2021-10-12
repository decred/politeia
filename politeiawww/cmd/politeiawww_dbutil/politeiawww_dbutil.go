// Copyright (c) 2017-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/decred/politeia/decredplugin"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/backend/gitbe"
	"github.com/decred/politeia/politeiawww/config"
	"github.com/decred/politeia/politeiawww/legacy/user"
	"github.com/decred/politeia/politeiawww/legacy/user/cockroachdb"
	"github.com/decred/politeia/politeiawww/legacy/user/localdb"
	mysqldb "github.com/decred/politeia/politeiawww/legacy/user/mysql"
	"github.com/decred/politeia/util"
	"github.com/google/uuid"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/marcopeereboom/sbox"
)

const (
	defaultMySQLHost       = "localhost:3306"
	defaultCockroachDBHost = "localhost:26257"
	// The following hardcoded CockroachDB paths are not ideal, instead they
	// should use OS specific paths:
	// `dcrutil.AppDataDir("cockroachdb", false)`, but since we use
	// `~/.cockroachdb` in our script to generate the CockroachDB certs (see
	// `/scripts/cockroachcerts.sh`) we are limited to use the same hardcoded
	// paths here.
	defaultRootCert   = "~/.cockroachdb/certs/clients/politeiawww/ca.crt"
	defaultClientCert = "~/.cockroachdb/certs/clients/politeiawww/client.politeiawww.crt"
	defaultClientKey  = "~/.cockroachdb/certs/clients/politeiawww/client.politeiawww.key"

	// Politeia repo info
	commentsJournalFilename = "comments.journal"

	// Journal actions
	journalActionAdd = "add" // Add entry
	journalActionDel = "del" // Delete entry
)

var (
	defaultEncryptionKey = filepath.Join(config.DefaultHomeDir, "sbox.key")

	// Database options
	level     = flag.Bool("leveldb", false, "")
	cockroach = flag.Bool("cockroachdb", false, "")
	mysql     = flag.Bool("mysql", false, "")

	// Application options
	testnet         = flag.Bool("testnet", false, "")
	dataDir         = flag.String("datadir", config.DefaultDataDir, "")
	cockroachdbhost = flag.String("cockroachdbhost", defaultCockroachDBHost, "")
	mysqlhost       = flag.String("mysqlhost", defaultMySQLHost, "")

	rootCert      = flag.String("rootcert", defaultRootCert, "")
	clientCert    = flag.String("clientcert", defaultClientCert, "")
	clientKey     = flag.String("clientkey", defaultClientKey, "")
	encryptionKey = flag.String("encryptionkey", defaultEncryptionKey, "")
	password      = flag.String("password", "", "")

	// Commands
	addCredits       = flag.Bool("addcredits", false, "")
	dump             = flag.Bool("dump", false, "")
	setAdmin         = flag.Bool("setadmin", false, "")
	setEmail         = flag.Bool("setemail", false, "")
	stubUsers        = flag.Bool("stubusers", false, "")
	migrate          = flag.Bool("migrate", false, "")
	createKey        = flag.Bool("createkey", false, "")
	verifyIdentities = flag.Bool("verifyidentities", false, "")
	resetTotp        = flag.Bool("resettotp", false, "")

	chainParams *config.ChainParams // Active network
	userDB      user.Database
)

const usageMsg = `politeiawww_dbutil usage:
  Database options
    -leveldb
          Use LevelDB
    -cockroachdb
          Use CockroachDB
    -mysql
          Use MySQL

  Application options
    -testnet
          Use testnet database
    -datadir string
          politeiawww data directory
          (default osDataDir/politeiawww/data)
    -cockroachdbhost string
          CockroachDB ip:port 
          (default localhost:26257)
    -rootcert string
          File containing the CockroachDB SSL root cert
          (default ~/.cockroachdb/certs/clients/politeiawww/ca.crt)
    -clientcert string
          File containing the CockroachDB SSL client cert
          (default ~/.cockroachdb/certs/clients/politeiawww/client.politeiawww.crt)
    -clientkey string
          File containing the CockroachDB SSL client cert key
          (default ~/.cockroachdb/certs/clients/politeiawww/client.politeiawww.key)
    -encryptionkey string
          File containing the CockroachDB/MySQL encryption key
          (default osDataDir/politeiawww/sbox.key)
    -password string
          MySQL database password.
    -mysqlhost string
          MySQL ip:port 
          (default localhost:3306)

  Commands
    -addcredits
          Add proposal credits to a user's account
          Required DB flag : -leveldb, -cockroachdb or -mysql
          LevelDB args     : <email> <quantity>
          CockroachDB args : <username> <quantity>
    -setadmin
          Set the admin flag for a user
          Required DB flag : -leveldb, -cockroachdb or -mysql
          LevelDB args     : <email> <true/false>
          CockroachDB args : <username> <true/false>
    -setemail
          Set a user's email to the provided email address
          Required DB flag : -cockroachdb or -mysql
          CockroachDB args : <username> <email>
    -stubusers
          Create user stubs for the public keys in a politeia repo
          Required DB flag : -leveldb, -cockroachdb or -mysql
          LevelDB args     : <importDir>
          CockroachDB args : <importDir>
    -dump
          Dump the entire database or the contents of a specific user
          Required DB flag : -leveldb
          LevelDB args     : <username>
    -createkey
          Create a new encryption key that can be used to encrypt data at rest
          Required DB flag : None
          Args             : <destination (optional)>
                             (default osDataDir/politeiawww/sbox.key)
    -migrate
          Migrate from one user database to another
          Required DB flag : None
          Args             : <fromDB> <toDB>
                             Valid DBs are mysql, cockroachdb, leveldb
    -verifyidentities
          Verify a user's identities do not violate any politeia rules. Invalid
          identities are fixed.
          Required DB flag : -cockroachdb or -mysql
    -resettotp
          Reset a user's totp settings in case they are locked out and 
          confirm identity. 
          Required DB flag : -leveldb, -cockroachdb or -mysql
          LevelDB args     : <email>
          CockroachDB args : <username>
`

func cmdDump() error {
	// If email is provided, only dump that user.
	args := flag.Args()
	if len(args) == 1 {
		username := args[0]
		u, err := userDB.UserGetByUsername(username)

		if err != nil {
			return err
		}

		fmt.Printf("Key    : %v\n", username)
		fmt.Printf("Record : %v", spew.Sdump(u))
		return nil
	}

	err := userDB.AllUsers(func(u *user.User) {
		fmt.Printf("Key    : %v\n", u.Username)
		fmt.Printf("Record : %v\n", spew.Sdump(u))
	})
	if err != nil {
		return err
	}
	return nil
}

func cmdSetAdmin() error {
	args := flag.Args()
	if len(args) < 2 {
		flag.Usage()
		return nil
	}

	username := args[0]
	isAdmin := (strings.ToLower(args[1]) == "true" || args[1] == "1")

	u, err := userDB.UserGetByUsername(username)
	if err != nil {
		return err
	}

	u.Admin = isAdmin

	err = userDB.UserUpdate(*u)
	if err != nil {
		return err
	}

	fmt.Printf("User with username '%v' admin status updated "+
		"to %v\n", username, isAdmin)

	return nil
}

func cmdSetEmail() error {
	args := flag.Args()
	if len(args) < 2 {
		flag.Usage()
		return nil
	}

	if *level {
		return fmt.Errorf("this cannot be used with the -leveldb flag")
	}

	username := strings.ToLower(args[0])
	newEmail := strings.ToLower(args[1])

	u, err := userDB.UserGetByUsername(username)
	if err != nil {
		return err
	}

	u.Email = newEmail

	err = userDB.UserUpdate(*u)
	if err != nil {
		return err
	}

	fmt.Printf("User with username '%v' email successfully updated to '%v'\n",
		username, newEmail)
	fmt.Printf("politeiawww MUST BE restarted so the user email memory cache " +
		"gets updated; politeiad is fine and does not need to be restarted\n")

	return nil
}

func cmdAddCredits() error {
	args := flag.Args()
	if len(args) < 2 {
		flag.Usage()
		return nil
	}
	username := args[0]

	quantity, err := strconv.Atoi(args[1])
	if err != nil {
		return fmt.Errorf("parse int '%v' failed: %v",
			args[1], err)
	}
	// Lookup user
	u, err := userDB.UserGetByUsername(username)
	if err != nil {
		return err
	}

	// Create proposal credits
	ts := time.Now().Unix()
	c := make([]user.ProposalCredit, 0, quantity)
	for i := 0; i < quantity; i++ {
		c = append(c, user.ProposalCredit{
			PaywallID:     0,
			Price:         0,
			DatePurchased: ts,
			TxID:          "created_by_dbutil",
		})
	}
	u.UnspentProposalCredits = append(u.UnspentProposalCredits, c...)

	// Update database
	err = userDB.UserUpdate(*u)
	if err != nil {
		return fmt.Errorf("update user: %v", err)
	}

	fmt.Printf("%v proposal credits added to account %v\n",
		quantity, username)

	return nil
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

func cmdStubUsers() error {
	if len(flag.Args()) == 0 {
		return fmt.Errorf("must provide import directory")
	}

	// Parse import directory
	importDir := util.CleanAndExpandPath(flag.Arg(0))
	_, err := os.Stat(importDir)
	if err != nil {
		return err
	}

	// Walk import directory and compile all unique public
	// keys that are found.
	fmt.Printf("Walking import directory...\n")
	pubkeys := make(map[string]struct{})
	err = filepath.Walk(importDir,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			// Skip directories
			if info.IsDir() {
				return nil
			}

			switch info.Name() {
			case commentsJournalFilename:
				err := replayCommentsJournal(path, pubkeys)
				if err != nil {
					return err
				}
			}

			return nil
		})
	if err != nil {
		return fmt.Errorf("walk import dir: %v", err)
	}

	fmt.Printf("Stubbing users...\n")

	// update users on database
	var i int
	for k := range pubkeys {
		username := fmt.Sprintf("dbutil_user%v", i)
		email := username + "@example.com"
		id, err := identity.PublicIdentityFromString(k)
		if err != nil {
			return err
		}

		err = userDB.UserNew(user.User{
			ID:             uuid.New(),
			Email:          email,
			Username:       username,
			HashedPassword: []byte("password"),
			Admin:          false,
			Identities: []user.Identity{
				{
					Key:       id.Key,
					Activated: time.Now().Unix(),
				},
			},
		})
		if err != nil {
			return err
		}

		i++
	}

	fmt.Printf("Done!\n")
	return nil
}

func connectLevelDB() (user.Database, error) {
	_, err := os.Stat(*dataDir)
	if err != nil {
		if os.IsNotExist(err) {
			err = fmt.Errorf("leveldb dir not found: %v", *dataDir)
		}
		return nil, err
	}

	fmt.Printf("LevelDB     : %v\n", *dataDir)
	return localdb.New(*dataDir)
}

func connectCockroachDB() (user.Database, error) {
	err := validateCockroachParams()
	if err != nil {
		return nil, fmt.Errorf("new cockroachdb: %v", err)
	}

	fmt.Printf("CockroachDB : %v %v", *cockroachdbhost, chainParams.Name)

	return cockroachdb.New(*cockroachdbhost, chainParams.Name,
		*rootCert, *clientCert, *clientKey, *encryptionKey)
}

func connectMySQL() (user.Database, error) {
	err := validateMySQLParams()
	if err != nil {
		return nil, err
	}

	fmt.Printf("MySQL : %v %v\n", *mysqlhost, chainParams.Name)

	return mysqldb.New(*mysqlhost, *password, chainParams.Name, *encryptionKey)
}

func connectDB(typeDB string) (user.Database, error) {
	switch typeDB {
	case "leveldb":
		return connectLevelDB()

	case "cockroachdb":
		return connectCockroachDB()

	case "mysql":
		return connectMySQL()

	default:
		return nil, fmt.Errorf("invalid database type: %v", typeDB)
	}
}

func cmdMigrate() error {
	args := flag.Args()
	if len(args) < 2 {
		flag.Usage()
		return nil
	}

	fromType := args[0]
	toType := args[1]

	if fromType == toType {
		return fmt.Errorf("origin and destination databases can not " +
			"be the same")
	}

	// Connect to origin database.
	fromDB, err := connectDB(fromType)
	if err != nil {
		return err
	}
	defer fromDB.Close()

	// Connect to destination database.
	toDB, err := connectDB(toType)
	if err != nil {
		return err
	}
	defer toDB.Close()

	fmt.Printf("Migrating records from %v to %v...\n", fromType, toType)

	var users []user.User
	var paywallIndex uint64
	var userCount int

	// Populate the user slice from the origin database users.
	err = fromDB.AllUsers(func(u *user.User) {
		users = append(users, *u)
	})
	if err != nil {
		return fmt.Errorf("origin database allusers request: %v", err)
	}

	// Make sure the migration went ok.
	if len(users) == 0 {
		return fmt.Errorf("no users found in origin database")
	}

	for i := 0; i < len(users); i++ {
		u := users[i]
		// Check if username already exists in db. There was a
		// ~2 month period where a bug allowed for users to be
		// created with duplicate usernames.
		_, err = toDB.UserGetByUsername(u.Username)

		if u.PaywallAddressIndex > paywallIndex {
			paywallIndex = u.PaywallAddressIndex
		}
		switch err {
		case nil:
			for !errors.Is(err, user.ErrUserNotFound) {
				// Username is a duplicate. Allow for the username to be
				// updated here. The migration will fail if the username
				// is not unique.
				fmt.Printf("Username '%v' already exists. Username must be "+
					"updated for the following user before the migration can "+
					"continue.\n", u.Username)

				fmt.Printf("ID                 : %v\n", u.ID.String())
				fmt.Printf("Email              : %v\n", u.Email)
				fmt.Printf("Username           : %v\n", u.Username)
				fmt.Printf("Input new username : ")

				var input string
				r := bufio.NewReader(os.Stdin)
				input, err = r.ReadString('\n')
				if err != nil {
					return err
				}

				username := strings.TrimSuffix(input, "\n")
				u.Username = strings.ToLower(strings.TrimSpace(username))
				_, err = toDB.UserGetByUsername(u.Username)
			}

			fmt.Printf("Username updated to '%v'\n", u.Username)

		case user.ErrUserNotFound:
			// Username doesn't exist; continue
		default:
			return err
		}

		err = toDB.InsertUser(u)
		if err != nil {
			return fmt.Errorf("migrate user '%v': %v",
				u.ID, err)
		}
		userCount++
	}
	// If at least one user was migrated, update paywall address index in
	// destination database.
	if userCount > 0 {
		err = toDB.SetPaywallAddressIndex(paywallIndex)
		if err != nil {
			return fmt.Errorf("update paywall index '%v': %v", paywallIndex,
				err)
		}
	}

	fmt.Printf("Users migrated : %v\n", userCount)
	fmt.Printf("Paywall index  : %v\n", paywallIndex)
	fmt.Printf("Done!\n")

	return nil
}

func cmdCreateKey() error {
	path := defaultEncryptionKey
	args := flag.Args()
	if len(args) > 0 {
		path = util.CleanAndExpandPath(args[0])
	}

	// Don't allow overwriting an existing key
	_, err := os.Stat(path)
	if err == nil {
		return fmt.Errorf("file already exists; cannot "+
			"overwrite %v", path)
	}

	// Create a new key
	k, err := sbox.NewKey()
	if err != nil {
		return err
	}

	// Write hex encoded key to file
	err = ioutil.WriteFile(path, []byte(hex.EncodeToString(k[:])), 0644)
	if err != nil {
		return err
	}

	fmt.Printf("Encryption key saved to: %v\n", path)

	// Zero out encryption key
	util.Zero(k[:])
	k = nil

	return nil
}

func validateCockroachParams() error {
	// Validate host
	_, err := url.Parse(*cockroachdbhost)
	if err != nil {
		return fmt.Errorf("parse host '%v': %v",
			*cockroachdbhost, err)
	}

	// Validate root cert
	b, err := ioutil.ReadFile(*rootCert)
	if err != nil {
		return fmt.Errorf("read rootcert: %v", err)
	}

	block, _ := pem.Decode(b)
	_, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse rootcert: %v", err)
	}

	// Validate client key pair
	_, err = tls.LoadX509KeyPair(*clientCert, *clientKey)
	if err != nil {
		return fmt.Errorf("load key pair clientcert and "+
			"clientkey: %v", err)
	}

	// Ensure encryption key file exists
	if !util.FileExists(*encryptionKey) {
		return fmt.Errorf("file not found %v", *encryptionKey)
	}

	return nil
}

func validateMySQLParams() error {
	// Validate host.
	_, err := url.Parse(*mysqlhost)
	if err != nil {
		return fmt.Errorf("parse host '%v': %v", *mysqlhost, err)
	}

	// Validate password.
	if *password == "" {
		return fmt.Errorf("MySQL politeiawww user's password is missing;" +
			" use -password flag to provide it")
	}

	// Ensure encryption key file exists.
	if !util.FileExists(*encryptionKey) {
		return fmt.Errorf("file not found %v", *encryptionKey)
	}

	return nil
}

func cmdVerifyIdentities() error {
	args := flag.Args()
	if len(args) != 1 {
		return fmt.Errorf("invalid number of arguments; want <username>, got %v",
			args)
	}

	u, err := userDB.UserGetByUsername(args[0])
	if err != nil {
		return fmt.Errorf("UserGetByUsername(%v): %v",
			args[0], err)
	}

	// Verify inactive identities. There should only ever be one
	// inactive identity at a time. If more than one inactive identity
	// is found, deactivate all of them since it can't be determined
	// which one is the most recent.
	inactive := make(map[string]user.Identity, len(u.Identities)) // [pubkey]Identity
	for _, v := range u.Identities {
		if v.IsInactive() {
			inactive[v.String()] = v
		}
	}
	switch len(inactive) {
	case 0:
		fmt.Printf("0 inactive identities found; this is ok\n")
	case 1:
		fmt.Printf("1 inactive identity found; this is ok\n")
	default:
		fmt.Printf("%v inactive identities found\n", len(inactive))
		for _, v := range inactive {
			fmt.Printf("%v\n", v.String())
		}

		fmt.Printf("deactivating all inactive identities\n")

		for i, v := range u.Identities {
			if !v.IsInactive() {
				// Not an inactive identity
				continue
			}
			fmt.Printf("deactivating: %v\n", v.String())
			u.Identities[i].Deactivate()
		}
	}

	// Verify active identities. There should only ever be one active
	// identity at a time.
	active := make(map[string]user.Identity, len(u.Identities)) // [pubkey]Identity
	for _, v := range u.Identities {
		if v.IsActive() {
			active[v.String()] = v
		}
	}
	switch len(active) {
	case 0:
		fmt.Printf("0 active identities found; this is ok\n")
	case 1:
		fmt.Printf("1 active identity found; this is ok\n")
	default:
		fmt.Printf("%v active identities found\n", len(active))
		for _, v := range active {
			fmt.Printf("%v\n", v.String())
		}

		fmt.Printf("deactivating all but the most recent active identity\n")

		// Find most recent active identity
		var pubkey string
		var ts int64
		for _, v := range active {
			if v.Activated > ts {
				pubkey = v.String()
				ts = v.Activated
			}
		}

		// Deactivate all but the most recent active identity
		for i, v := range u.Identities {
			if !v.IsActive() {
				// Not an active identity
				continue
			}
			if pubkey == v.String() {
				// Most recent active identity
				continue
			}
			fmt.Printf("deactivating: %v\n", v.String())
			u.Identities[i].Deactivate()
		}
	}

	// Update user
	err = userDB.UserUpdate(*u)
	if err != nil {
		return fmt.Errorf("UserUpdate: %v", err)
	}

	return nil
}

func cmdResetTOTP() error {
	args := flag.Args()
	if len(args) != 1 {
		return fmt.Errorf("invalid number of arguments; want <username>, got %v",
			args)
	}

	username := args[0]
	u, err := userDB.UserGetByUsername(username)
	if err != nil {
		return err
	}

	u.TOTPLastUpdated = nil
	u.TOTPSecret = ""
	u.TOTPType = 0
	u.TOTPVerified = false

	err = userDB.UserUpdate(*u)
	if err != nil {
		return err
	}

	fmt.Printf("User with username '%v' reset totp\n", username)

	return nil
}

func _main() error {
	flag.Parse()

	// Setup the active network
	if *testnet {
		chainParams = &config.MainNetParams
	} else {
		chainParams = &config.TestNet3Params
	}

	// Clean and expand all file paths
	*dataDir = util.CleanAndExpandPath(*dataDir)
	*rootCert = util.CleanAndExpandPath(*rootCert)
	*clientCert = util.CleanAndExpandPath(*clientCert)
	*clientKey = util.CleanAndExpandPath(*clientKey)
	*encryptionKey = util.CleanAndExpandPath(*encryptionKey)

	// Namespace data dir by network
	*dataDir = filepath.Join(*dataDir, chainParams.Name)

	// Validate database selection.
	switch {
	case *mysql && *cockroach, *level && *mysql, *level && *cockroach,
		*level && *cockroach && *mysql:
		fmt.Println(mysql, cockroach)
		return fmt.Errorf("multiple database flags; must use one of the " +
			"following: -leveldb, -mysql or -cockroachdb")
	}

	switch {
	case *addCredits || *setAdmin || *stubUsers || *resetTotp:
		// These commands must be run with -cockroachdb, -mysql or -leveldb.
		if !*level && !*cockroach && !*mysql {
			return fmt.Errorf("missing database flag; must use " +
				"-leveldb, -cockroachdb or -mysql")
		}
	case *dump:
		// These commands must be run with -leveldb.
		if !*level {
			return fmt.Errorf("missing database flag; must use " +
				"-leveldb with this command")
		}
	case *verifyIdentities, *setEmail:
		// These commands must be run with either -cockroachdb or -mysql.
		if !*cockroach || *level {
			return fmt.Errorf("invalid database flag; must use " +
				"either -mysql or -cockroachdb with this command")
		}
	case *migrate || *createKey:
		// These commands must be run without a database flag.
		if *level || *cockroach || *mysql {
			return fmt.Errorf("unexpected database flag found; " +
				"remove database flag -leveldb, -mysql and -cockroachdb")
		}
	}

	// Connect to database
	var err error
	switch {
	case *level:
		userDB, err = connectLevelDB()

	case *cockroach:
		userDB, err = connectCockroachDB()

	case *mysql:
		userDB, err = connectMySQL()

	}
	if err != nil {
		return err
	}
	if userDB != nil {
		defer userDB.Close()
	}

	// Run command
	switch {
	case *addCredits:
		return cmdAddCredits()
	case *dump:
		return cmdDump()
	case *setAdmin:
		return cmdSetAdmin()
	case *setEmail:
		return cmdSetEmail()
	case *stubUsers:
		return cmdStubUsers()
	case *migrate:
		return cmdMigrate()
	case *createKey:
		return cmdCreateKey()
	case *verifyIdentities:
		return cmdVerifyIdentities()
	case *resetTotp:
		return cmdResetTOTP()
	default:
		fmt.Printf("invalid command\n")
		flag.Usage()
	}

	return nil
}

func main() {
	// Custom usage message
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, usageMsg)
	}

	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
