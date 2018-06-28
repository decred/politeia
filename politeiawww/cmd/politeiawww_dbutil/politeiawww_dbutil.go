package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/decred/politeia/politeiawww/database"
	"golang.org/x/crypto/bcrypt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/politeia/politeiawww/database/localdb"
	"github.com/decred/politeia/politeiawww/sharedconfig"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

var (
	dataDir            = flag.String("datadir", sharedconfig.DefaultDataDir, "Specify the politeiawww data directory.")
	dumpDb             = flag.Bool("dump", false, "Dump the entire politeiawww database contents or contents for a specific user. Parameters: [email]")
	setAdmin           = flag.Bool("setadmin", false, "Set the admin flag for a user. Parameters: <email> <true/false>")
	clearPaywall       = flag.Bool("clearpaywall", false, "Clear the paywall fields for a user given his email.")
	newUser            = flag.Bool("newuser", false, "Create a new user. Parameters: <email> <username> <password>")
	expireVerification = flag.Bool("expireverification", false, "Set the verification expiry fields to a date in the past. Parameters: <email>")
	testnet            = flag.Bool("testnet", false, "Whether to check the testnet database or not.")
	dbDir              = ""
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
		} else if string(key) == localdb.LastUserIdKey {
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

func newUserAction() error {
	args := flag.Args()
	if len(args) < 3 {
		flag.Usage()
		return nil
	}

	email := args[0]
	username := args[1]
	password := args[2]

	userdb, err := leveldb.OpenFile(dbDir, &opt.Options{
		ErrorIfMissing: true,
	})
	if err != nil {
		return err
	}
	defer userdb.Close()

	_, err = userdb.Get([]byte(email), nil)
	if err == nil {
		return fmt.Errorf("user with email %v already exists in the database", email)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password),
		bcrypt.MinCost)
	if err != nil {
		return err
	}

	user, err := localdb.EncodeUser(database.User{
		Email:            email,
		Username:         username,
		HashedPassword:   hashedPassword,
		NewUserPaywallTx: "cleared_by_dbutil",
	})
	if err != nil {
		return err
	}

	if err = userdb.Put([]byte(email), user, nil); err != nil {
		return err
	}

	fmt.Printf("New user created with email %v\n", email)
	return nil
}

func clearPaywallAction() error {
	args := flag.Args()
	if len(args) < 1 {
		flag.Usage()
		return nil
	}

	email := args[0]

	userdb, err := leveldb.OpenFile(dbDir, &opt.Options{
		ErrorIfMissing: true,
	})
	if err != nil {
		return err
	}
	defer userdb.Close()

	b, err := userdb.Get([]byte(email), nil)
	if err != nil {
		return fmt.Errorf("user with email %v not found in the database", email)
	}

	u, err := localdb.DecodeUser(b)
	if err != nil {
		return err
	}

	u.NewUserPaywallAddress = ""
	u.NewUserPaywallTx = "cleared_by_dbutil"

	b, err = localdb.EncodeUser(*u)
	if err != nil {
		return err
	}

	if err = userdb.Put([]byte(email), b, nil); err != nil {
		return err
	}

	fmt.Printf("Cleared paywall for user with email %v\n", email)
	return nil
}

func expireVerificationAction() error {
	args := flag.Args()
	if len(args) < 1 {
		flag.Usage()
		return nil
	}

	email := args[0]

	userdb, err := leveldb.OpenFile(dbDir, &opt.Options{
		ErrorIfMissing: true,
	})
	if err != nil {
		return err
	}
	defer userdb.Close()

	b, err := userdb.Get([]byte(email), nil)
	if err != nil {
		return fmt.Errorf("user with email %v not found in the database", email)
	}

	u, err := localdb.DecodeUser(b)
	if err != nil {
		return err
	}

	// -168 hours = 7 days in the past
	expiredTime := time.Now().Add(-168 * time.Hour).Unix()
	if u.NewUserVerificationExpiry != 0 {
		u.NewUserVerificationExpiry = expiredTime
	}
	if u.ResetPasswordVerificationExpiry != 0 {
		u.ResetPasswordVerificationExpiry = expiredTime
	}
	if u.UpdateKeyVerificationExpiry != 0 {
		u.UpdateKeyVerificationExpiry = expiredTime
	}

	b, err = localdb.EncodeUser(*u)
	if err != nil {
		return err
	}

	if err = userdb.Put([]byte(email), b, nil); err != nil {
		return err
	}

	fmt.Printf("Marked verification fields as expired for user %v\n", email)
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
		return fmt.Errorf("database directory does not exist: %v",
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
	} else if *newUser {
		if err := newUserAction(); err != nil {
			return err
		}
	} else if *expireVerification {
		if err := expireVerificationAction(); err != nil {
			return err
		}
	} else if *clearPaywall {
		if err := clearPaywallAction(); err != nil {
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
