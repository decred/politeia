// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/politeia/decredplugin"
	"github.com/decred/politeia/politeiad/backend/gitbe"
	"github.com/decred/politeia/politeiawww/sharedconfig"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/politeiawww/user/localdb"
	"github.com/decred/politeia/util"
	"github.com/google/uuid"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

const (
	commentsJournalFilename = "comments.journal"
	proposalMDFilename      = "00.metadata.txt"

	// Journal actions
	journalActionAdd     = "add"     // Add entry
	journalActionDel     = "del"     // Delete entry
	journalActionAddLike = "addlike" // Add comment like
)

var (
	addCredits = flag.Bool("addcredits", false, "Add proposal credits to a user's account. Parameters: <email> <quantity>")
	dataDir    = flag.String("datadir", sharedconfig.DefaultDataDir, "Specify the politeiawww data directory.")
	dumpDb     = flag.Bool("dump", false, "Dump the entire politeiawww database contents or contents for a specific user. Parameters: [email]")
	setAdmin   = flag.Bool("setadmin", false, "Set the admin flag for a user. Parameters: <email> <true/false>")
	stubUsers  = flag.Bool("stubusers", false, "Create user stubs for the public keys in a politeia repo. Parameters: <importDir>")
	testnet    = flag.Bool("testnet", false, "Whether to check the testnet database or not.")
	dbDir      = ""
)

type proposalMetadata struct {
	Version   uint64 `json:"version"`   // Version of this struct
	Timestamp int64  `json:"timestamp"` // Last update of proposal
	Name      string `json:"name"`      // Generated proposal name
	PublicKey string `json:"publickey"` // Key used for signature
	Signature string `json:"signature"` // Signature of merkle root
}

func dumpAction() error {
	userdb, err := leveldb.OpenFile(dbDir, &opt.Options{
		ErrorIfMissing: true,
	})
	if err != nil {
		return err
	}
	defer userdb.Close()

	// If email is provided, only dump that user.
	args := flag.Args()
	if len(args) == 1 {
		email := []byte(args[0])
		value, err := userdb.Get(email, nil)
		if err != nil {
			return err
		}

		u, err := localdb.DecodeUser(value)
		if err != nil {
			return err
		}

		fmt.Printf("Key    : %v\n", hex.EncodeToString(email))
		fmt.Printf("Record : %v", spew.Sdump(u))
		return nil
	}

	iter := userdb.NewIterator(nil, nil)
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
			u, err := localdb.DecodeUser(value)
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

func setAdminAction() error {
	args := flag.Args()
	if len(args) < 2 {
		flag.Usage()
		return nil
	}

	email := args[0]
	admin := strings.ToLower(args[1]) == "true" || args[1] == "1"

	userdb, err := leveldb.OpenFile(dbDir, &opt.Options{
		ErrorIfMissing: true,
	})
	if err != nil {
		return err
	}
	defer userdb.Close()

	b, err := userdb.Get([]byte(email), nil)
	if err != nil {
		fmt.Printf("User with email %v not found in the database\n", email)
	}

	u, err := localdb.DecodeUser(b)
	if err != nil {
		return err
	}

	u.Admin = admin

	b, err = localdb.EncodeUser(*u)
	if err != nil {
		return err
	}

	if err = userdb.Put([]byte(email), b, nil); err != nil {
		return err
	}

	if admin {
		fmt.Printf("User with email %v elevated to admin\n", email)
	} else {
		fmt.Printf("User with email %v removed from admin\n", email)
	}

	return nil
}

func addCreditsAction() error {
	// Handle cli args.
	args := flag.Args()
	if len(args) < 2 {
		flag.Usage()
		return nil
	}

	email := args[0]
	quantity, err := strconv.Atoi(args[1])
	if err != nil {
		return fmt.Errorf("quantity must parse to an int")
	}

	// Open connection to user db.
	db, err := leveldb.OpenFile(dbDir, &opt.Options{
		ErrorIfMissing: true,
	})
	if err != nil {
		return err
	}
	defer db.Close()

	// Fetch user from db.
	u, err := db.Get([]byte(email), nil)
	if err != nil {
		return err
	}
	usr, err := localdb.DecodeUser(u)
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
	u, err = localdb.EncodeUser(*usr)
	if err != nil {
		return err
	}
	if err = db.Put([]byte(email), u, nil); err != nil {
		return err
	}

	fmt.Printf("%v proposal credits added to %v's account\n", quantity, email)
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

func stubUsersAction() error {
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

	// Open db connection
	userdb, err := leveldb.OpenFile(dbDir,
		&opt.Options{
			ErrorIfMissing: true,
		})
	if err != nil {
		return err
	}
	defer userdb.Close()

	// Create a user stub for each pubkey
	fmt.Printf("Stubbing users...\n")
	var i int
	for k := range pubkeys {
		username := fmt.Sprintf("dbutil_user%v", i)
		email := username + "@example.com"
		id, err := util.IdentityFromString(k)
		if err != nil {
			return err
		}

		b, err := localdb.EncodeUser(user.User{
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

		err = userdb.Put([]byte(email), b, nil)
		if err != nil {
			return err
		}

		i++
	}

	fmt.Printf("Done!\n")
	return nil
}

func _main() error {
	flag.Parse()

	var net string
	if *testnet {
		net = chaincfg.TestNet3Params.Name
	} else {
		net = chaincfg.MainNetParams.Name
	}

	dbDir = filepath.Join(*dataDir, net, localdb.UserdbPath)
	fmt.Printf("Database: %v\n", dbDir)

	if _, err := os.Stat(dbDir); os.IsNotExist(err) {
		return fmt.Errorf("database directory does not exist: %v",
			dbDir)
	}

	switch {
	case *addCredits:
		return addCreditsAction()
	case *dumpDb:
		return dumpAction()
	case *setAdmin:
		return setAdminAction()
	case *stubUsers:
		return stubUsersAction()
	default:
		flag.Usage()
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
