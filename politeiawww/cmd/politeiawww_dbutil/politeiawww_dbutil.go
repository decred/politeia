// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
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
	"github.com/decred/dcrd/chaincfg"
	"github.com/thi4go/politeia/decredplugin"
	"github.com/thi4go/politeia/politeiad/backend/gitbe"
	"github.com/thi4go/politeia/politeiawww/sharedconfig"
	"github.com/thi4go/politeia/politeiawww/user"
	"github.com/thi4go/politeia/politeiawww/user/cockroachdb"
	"github.com/thi4go/politeia/politeiawww/user/localdb"
	"github.com/thi4go/politeia/util"
	"github.com/google/uuid"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/marcopeereboom/sbox"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

const (
	defaultHost       = "localhost:26257"
	defaultRootCert   = "~/.cockroachdb/certs/clients/politeiawww/ca.crt"
	defaultClientCert = "~/.cockroachdb/certs/clients/politeiawww/client.politeiawww.crt"
	defaultClientKey  = "~/.cockroachdb/certs/clients/politeiawww/client.politeiawww.key"

	// Politeia repo info
	commentsJournalFilename = "comments.journal"
	proposalMDFilename      = "00.metadata.txt"

	// Journal actions
	journalActionAdd     = "add"     // Add entry
	journalActionDel     = "del"     // Delete entry
	journalActionAddLike = "addlike" // Add comment like
)

var (
	defaultHomeDir       = sharedconfig.DefaultHomeDir
	defaultDataDir       = sharedconfig.DefaultDataDir
	defaultEncryptionKey = filepath.Join(defaultHomeDir, "sbox.key")

	// Database options
	level     = flag.Bool("leveldb", false, "")
	cockroach = flag.Bool("cockroachdb", false, "")

	// Application options
	testnet       = flag.Bool("testnet", false, "")
	dataDir       = flag.String("datadir", defaultDataDir, "")
	host          = flag.String("host", defaultHost, "")
	rootCert      = flag.String("rootcert", defaultRootCert, "")
	clientCert    = flag.String("clientcert", defaultClientCert, "")
	clientKey     = flag.String("clientkey", defaultClientKey, "")
	encryptionKey = flag.String("encryptionkey", defaultEncryptionKey, "")

	// Commands
	addCredits       = flag.Bool("addcredits", false, "")
	dump             = flag.Bool("dump", false, "")
	setAdmin         = flag.Bool("setadmin", false, "")
	stubUsers        = flag.Bool("stubusers", false, "")
	migrate          = flag.Bool("migrate", false, "")
	createKey        = flag.Bool("createkey", false, "")
	verifyIdentities = flag.Bool("verifyidentities", false, "")

	network string // Mainnet or testnet3
	// XXX ldb should be abstracted away. dbutil commands should use
	// the user.Database interface instead.
	ldb    *leveldb.DB
	userDB user.Database
)

const usageMsg = `politeiawww_dbutil usage:
  Database options
    -leveldb
          Use LevelDB
    -cockroachdb
          Use CockroachDB

  Application options
    -testnet
          Use testnet database
    -datadir string
          politeiawww data directory
		      (default osDataDir/politeiawww/data)
    -host string
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
          File containing the CockroachDB encryption key
          (default osDataDir/politeiawww/sbox.key)

  Commands
    -addcredits
          Add proposal credits to a user's account
          Required DB flag : -leveldb or -cockroachdb
          LevelDB args     : <email> <quantity>
          CockroachDB args : <username> <quantity>
    -setadmin
          Set the admin flag for a user
          Required DB flag : -leveldb or -cockroachdb
          LevelDB args     : <email> <true/false>
          CockroachDB args : <username> <true/false>
    -stubusers
          Create user stubs for the public keys in a politeia repo
          Required DB flag : -leveldb or -cockroachdb
          LevelDB args     : <importDir>
          CockroachDB args : <importDir>
    -dump
          Dump the entire database or the contents of a specific user
          Required DB flag : -leveldb
          LevelDB args     : <email>
    -createkey
          Create a new encryption key that can be used to encrypt data at rest
          Required DB flag : None
          Args             : <destination (optional)>
                             (default osDataDir/politeiawww/sbox.key)
    -migrate
          Migrate a LevelDB user database to CockroachDB
          Required DB flag : None
          Args             : None

     -verifyidentities
          Verify a user's identities do not violate any politeia rules. Invalid
          identities are fixed.
          Required DB flag : -cockroachdb
          Args             : <username>
`

type proposalMetadata struct {
	Version   uint64 `json:"version"`   // Version of this struct
	Timestamp int64  `json:"timestamp"` // Last update of proposal
	Name      string `json:"name"`      // Generated proposal name
	PublicKey string `json:"publickey"` // Key used for signature
	Signature string `json:"signature"` // Signature of merkle root
}

func cmdDump() error {
	// If email is provided, only dump that user.
	args := flag.Args()
	if len(args) == 1 {
		email := []byte(args[0])
		value, err := ldb.Get(email, nil)
		if err != nil {
			return err
		}

		u, err := user.DecodeUser(value)
		if err != nil {
			return err
		}

		fmt.Printf("Key    : %v\n", hex.EncodeToString(email))
		fmt.Printf("Record : %v", spew.Sdump(u))
		return nil
	}

	iter := ldb.NewIterator(nil, nil)
	for iter.Next() {
		fmt.Printf("%v\n", strings.Repeat("=", 80))
		key := iter.Key()
		value := iter.Value()

		switch string(key) {
		case localdb.UserVersionKey:
			v, err := localdb.DecodeVersion(value)
			if err != nil {
				return err
			}

			fmt.Printf("Key    : %v\n", string(key))
			fmt.Printf("Record : %v\n", spew.Sdump(v))
		case localdb.LastPaywallAddressIndex:
			fmt.Printf("Key    : %v\n", string(key))
			fmt.Printf("Record : %v\n", binary.LittleEndian.Uint64(value))
		default:
			u, err := user.DecodeUser(value)
			if err != nil {
				return err
			}

			fmt.Printf("Key    : %v\n", hex.EncodeToString(key))
			fmt.Printf("Record : %v", spew.Sdump(u))
		}
	}
	iter.Release()
	return iter.Error()
}

func levelSetAdmin(email string, isAdmin bool) error {
	b, err := ldb.Get([]byte(email), nil)
	if err != nil {
		return fmt.Errorf("user email '%v' not found", email)
	}

	u, err := user.DecodeUser(b)
	if err != nil {
		return err
	}

	u.Admin = isAdmin

	b, err = user.EncodeUser(*u)
	if err != nil {
		return err
	}

	err = ldb.Put([]byte(email), b, nil)
	if err != nil {
		return err
	}

	fmt.Printf("User with email '%v' admin status updated "+
		"to %v\n", email, isAdmin)

	return nil
}

func cockroachSetAdmin(username string, isAdmin bool) error {
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

func cmdSetAdmin() error {
	args := flag.Args()
	if len(args) < 2 {
		flag.Usage()
		return nil
	}

	isAdmin := (strings.ToLower(args[1]) == "true" || args[1] == "1")
	switch {
	case *level:
		return levelSetAdmin(args[0], isAdmin)
	case *cockroach:
		return cockroachSetAdmin(args[0], isAdmin)
	}

	return nil
}

func levelAddCredits(email string, quantity int) error {
	// Fetch user from db.
	u, err := ldb.Get([]byte(email), nil)
	if err != nil {
		return err
	}

	usr, err := user.DecodeUser(u)
	if err != nil {
		return err
	}

	// Create proposal credits.
	c := make([]user.ProposalCredit, quantity)
	timestamp := time.Now().Unix()
	for i := 0; i < quantity; i++ {
		c[i] = user.ProposalCredit{
			PaywallID:     0,
			Price:         0,
			DatePurchased: timestamp,
			TxID:          "created_by_dbutil",
		}
	}
	usr.UnspentProposalCredits = append(usr.UnspentProposalCredits, c...)

	// Write user record to db.
	u, err = user.EncodeUser(*usr)
	if err != nil {
		return err
	}
	if err = ldb.Put([]byte(email), u, nil); err != nil {
		return err
	}

	fmt.Printf("%v proposal credits added to account %v\n",
		quantity, email)
	return nil
}

func cockroachAddCredits(username string, quantity int) error {
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

func cmdAddCredits() error {
	args := flag.Args()
	if len(args) < 2 {
		flag.Usage()
		return nil
	}

	quantity, err := strconv.Atoi(args[1])
	if err != nil {
		return fmt.Errorf("parse int '%v' failed: %v",
			args[1], err)
	}

	switch {
	case *level:
		return levelAddCredits(args[0], quantity)
	case *cockroach:
		return cockroachAddCredits(args[0], quantity)
	}

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
		if err == io.EOF {
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

		case journalActionAddLike:
			var lc decredplugin.LikeComment
			err = d.Decode(&lc)
			if err != nil {
				return fmt.Errorf("journal addlike: %v", err)
			}
			pubkeys[lc.PublicKey] = struct{}{}

		default:
			return fmt.Errorf("invalid action: %v",
				action.Action)
		}
	}

	return nil
}

func levelStubUsers(pubkeys map[string]struct{}) error {
	var i int
	for k := range pubkeys {
		username := fmt.Sprintf("dbutil_user%v", i)
		email := username + "@example.com"
		id, err := util.IdentityFromString(k)
		if err != nil {
			return err
		}

		b, err := user.EncodeUser(user.User{
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

		err = ldb.Put([]byte(email), b, nil)
		if err != nil {
			return err
		}

		i++
	}

	fmt.Printf("Done!\n")
	return nil
}

func cockroachStubUsers(pubkeys map[string]struct{}) error {
	var i int
	for k := range pubkeys {
		username := fmt.Sprintf("dbutil_user%v", i)
		email := username + "@example.com"
		id, err := util.IdentityFromString(k)
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
			case proposalMDFilename:
				b, err := ioutil.ReadFile(path)
				if err != nil {
					return err
				}

				var md proposalMetadata
				err = json.Unmarshal(b, &md)
				if err != nil {
					return fmt.Errorf("proposal md: %v", err)
				}
				pubkeys[md.PublicKey] = struct{}{}
			}

			return nil
		})
	if err != nil {
		return fmt.Errorf("walk import dir: %v", err)
	}

	fmt.Printf("Stubbing users...\n")
	switch {
	case *level:
		return levelStubUsers(pubkeys)
	case *cockroach:
		return cockroachStubUsers(pubkeys)
	}

	return nil
}

func cmdMigrate() error {
	// Connect to LevelDB
	dbDir := filepath.Join(*dataDir, network, localdb.UserdbPath)
	_, err := os.Stat(dbDir)
	if err != nil {
		if os.IsNotExist(err) {
			err = fmt.Errorf("leveldb dir not found: %v", dbDir)
		}
		return err
	}

	ldb, err = leveldb.OpenFile(dbDir,
		&opt.Options{
			ErrorIfMissing: true,
		})
	if err != nil {
		return err
	}
	defer ldb.Close()

	// Connect to CockroachDB
	err = validateCockroachParams()
	if err != nil {
		return err
	}
	cdb, err := cockroachdb.New(*host, network, *rootCert,
		*clientCert, *clientKey, *encryptionKey)
	if err != nil {
		return fmt.Errorf("new cockroachdb: %v", err)
	}
	defer cdb.Close()

	fmt.Printf("LevelDB     : %v\n", dbDir)
	fmt.Printf("CockroachDB : %v %v\n", *host, network)
	fmt.Printf("Migrating records from LevelDB to CockroachDB...\n")

	// Migrate LevelDB records to CockroachDB
	var paywallIndex uint64
	var userCount int
	iter := ldb.NewIterator(nil, nil)
	for iter.Next() {
		key := iter.Key()
		value := iter.Value()

		switch string(key) {
		case localdb.UserVersionKey:
			// Version record; ignore
		case localdb.LastPaywallAddressIndex:
			// Paywall address index record
			paywallIndex = binary.LittleEndian.Uint64(value)
			err := cdb.SetPaywallAddressIndex(paywallIndex)
			if err != nil {
				return fmt.Errorf("set paywall index: %v", err)
			}
		default:
			// User record
			u, err := user.DecodeUser(value)
			if err != nil {
				return fmt.Errorf("decode user '%v': %v",
					value, err)
			}

			// Check if username already exists in db. There was a
			// ~2 month period where a bug allowed for users to be
			// created with duplicate usernames.
			_, err = cdb.UserGetByUsername(u.Username)
			switch err {
			case nil:
				for err != user.ErrUserNotFound {
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
					_, err = cdb.UserGetByUsername(u.Username)
				}

				fmt.Printf("Username updated to '%v'\n", u.Username)

			case user.ErrUserNotFound:
				// Username doesn't exist; continue
			default:
				return err
			}

			err = cdb.InsertUser(*u)
			if err != nil {
				return fmt.Errorf("migrate user '%v': %v",
					u.ID, err)
			}
			userCount++
		}
	}

	// Make sure the migration went ok.
	if userCount == 0 {
		return fmt.Errorf("no users found in leveldb")
	}

	if paywallIndex == 0 {
		return fmt.Errorf("paywall address index not found")
	}

	fmt.Printf("Users migrated : %v\n", userCount)
	fmt.Printf("Paywall index  : %v\n", paywallIndex)
	fmt.Printf("Done!\n")

	iter.Release()
	return iter.Error()
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
	_, err := url.Parse(*host)
	if err != nil {
		return fmt.Errorf("parse host '%v': %v",
			*host, err)
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

func _main() error {
	flag.Parse()

	*dataDir = util.CleanAndExpandPath(*dataDir)
	*rootCert = util.CleanAndExpandPath(*rootCert)
	*clientCert = util.CleanAndExpandPath(*clientCert)
	*clientKey = util.CleanAndExpandPath(*clientKey)
	*encryptionKey = util.CleanAndExpandPath(*encryptionKey)

	if *testnet {
		network = chaincfg.TestNet3Params.Name
	} else {
		network = chaincfg.MainNetParams.Name
	}

	// Validate database selection
	if *level && *cockroach {
		return fmt.Errorf("database choice cannot be both " +
			"-leveldb and -cockroachdb")
	}

	switch {
	case *addCredits || *setAdmin || *stubUsers:
		// These commands must be run with -cockroachdb or -leveldb
		if !*level && !*cockroach {
			return fmt.Errorf("missing database flag; must use " +
				"either -leveldb or -cockroachdb")
		}
	case *dump:
		// These commands must be run with -leveldb
		if !*level {
			return fmt.Errorf("missing database flag; must use " +
				"-leveldb with this command")
		}
	case *verifyIdentities:
		// These commands must be run with -cockroachdb
		if !*cockroach || *level {
			return fmt.Errorf("invalid database flag; must use " +
				"-cockroachdb with this command")
		}
	case *migrate || *createKey:
		// These commands must be run without a database flag
		if *level || *cockroach {
			return fmt.Errorf("unexpected database flag found; " +
				"remove database flag -leveldb and -cockroachdb")
		}
	}

	// Connect to database
	switch {
	case *level:
		dbDir := filepath.Join(*dataDir, network, localdb.UserdbPath)
		fmt.Printf("Database: %v\n", dbDir)

		_, err := os.Stat(dbDir)
		if err != nil {
			if os.IsNotExist(err) {
				err = fmt.Errorf("leveldb dir not found: %v", dbDir)
			}
			return err
		}
		ldb, err = leveldb.OpenFile(dbDir,
			&opt.Options{
				ErrorIfMissing: true,
			})
		if err != nil {
			return err
		}
		defer ldb.Close()

	case *cockroach:
		err := validateCockroachParams()
		if err != nil {
			return err
		}
		db, err := cockroachdb.New(*host, network, *rootCert,
			*clientCert, *clientKey, *encryptionKey)
		if err != nil {
			return fmt.Errorf("new cockroachdb: %v", err)
		}
		userDB = db
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
	case *stubUsers:
		return cmdStubUsers()
	case *migrate:
		return cmdMigrate()
	case *createKey:
		return cmdCreateKey()
	case *verifyIdentities:
		return cmdVerifyIdentities()
	default:
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
