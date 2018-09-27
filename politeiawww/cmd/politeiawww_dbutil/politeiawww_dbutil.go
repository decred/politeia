package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/decred/politeia/politeiawww/database"

	"github.com/davecgh/go-spew/spew"
	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/politeia/politeiawww/database/localdb"
	"github.com/decred/politeia/politeiawww/sharedconfig"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

var (
	addCredits = flag.Bool("addcredits", false, "Add proposal credits to a user's account. Parameters: <email> <quantity>")
	dataDir    = flag.String("datadir", sharedconfig.DefaultDataDir, "Specify the politeiawww data directory.")
	dumpDb     = flag.Bool("dump", false, "Dump the entire politeiawww database contents or contents for a specific user. Parameters: [email]")
	setAdmin   = flag.Bool("setadmin", false, "Set the admin flag for a user. Parameters: <email> <true/false>")
	testnet    = flag.Bool("testnet", false, "Whether to check the testnet database or not.")
	dbDir      = ""
)

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

		if string(key) == localdb.UserVersionKey {
			v, err := localdb.DecodeVersion(value)
			if err != nil {
				return err
			}

			fmt.Printf("Key    : %v\n", string(key))
			fmt.Printf("Record : %v\n", spew.Sdump(v))
		} else if string(key) == localdb.LastPaywallAddressIndex {
			fmt.Printf("Key    : %v\n", string(key))
			fmt.Printf("Record : %v\n", binary.LittleEndian.Uint64(value))
		} else {
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
	user, err := localdb.DecodeUser(u)
	if err != nil {
		return err
	}

	// Create proposal credits.
	c := make([]database.ProposalCredit, quantity)
	timestamp := time.Now().Unix()
	for i := 0; i < quantity; i++ {
		c[i] = database.ProposalCredit{
			PaywallID:     0,
			Price:         0,
			DatePurchased: timestamp,
			TxID:          "created_by_dbutil",
		}
	}
	user.UnspentProposalCredits = append(user.UnspentProposalCredits, c...)

	// Write user record to db.
	u, err = localdb.EncodeUser(*user)
	if err != nil {
		return err
	}
	if err = db.Put([]byte(email), u, nil); err != nil {
		return err
	}

	fmt.Printf("%v proposal credits added to %v's account\n", quantity, email)
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

	if *addCredits {
		if err := addCreditsAction(); err != nil {
			return err
		}
	} else if *dumpDb {
		if err := dumpAction(); err != nil {
			return err
		}
	} else if *setAdmin {
		if err := setAdminAction(); err != nil {
			return err
		}
	} else {
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
