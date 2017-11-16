package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/politeia/politeiawww/database/localdb"
	"github.com/decred/politeia/politeiawww/sharedconfig"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

var (
	dataDir  = flag.String("datadir", sharedconfig.DefaultDataDir, "Specify the politeiawww data directory.")
	dumpDb   = flag.Bool("dump", false, "Dump the entire politeiawww database contents.")
	setAdmin = flag.Bool("setadmin", false, "Set the admin flag for a user. Parameters: <email> <true/false>")
	testnet  = flag.Bool("testnet", false, "Whether to check the testnet database or not.")
	dbDir    = ""
)

func dumpAction() error {
	userdb, err := leveldb.OpenFile(dbDir, &opt.Options{
		ErrorIfMissing: true,
	})
	if err != nil {
		return err
	}
	defer userdb.Close()

	iter := userdb.NewIterator(nil, nil)
	for iter.Next() {
		fmt.Printf("%v\n", strings.Repeat("=", 80))
		key := iter.Key()
		value := iter.Value()

		u, err := localdb.DecodeUser(value)
		if err != nil {
			return err
		}

		fmt.Printf("Key    : %v\n", hex.EncodeToString(key))
		fmt.Printf("Record : %v", spew.Sdump(u))
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

func _main() error {
	flag.Parse()

	var net string
	if *testnet {
		net = chaincfg.TestNet2Params.Name
	} else {
		net = chaincfg.MainNetParams.Name
	}

	dbDir = filepath.Join(*dataDir, net, localdb.UserdbPath)
	fmt.Printf("Database: %v\n", dbDir)

	if _, err := os.Stat(dbDir); os.IsNotExist(err) {
		return fmt.Errorf("Database directory does not exist: %v",
			dbDir)
	}

	if *dumpDb {
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
	if err := _main(); err != nil {
		log.Fatal(err)
	}
}
