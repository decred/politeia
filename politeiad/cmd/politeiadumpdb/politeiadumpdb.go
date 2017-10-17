package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/politeia/politeiad/backend/gitbe"
	"github.com/marcopeereboom/lockfile"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

var (
	defaultHomeDir = dcrutil.AppDataDir("politeiad", false)
	dbDirectory    = flag.String("d", filepath.Join(defaultHomeDir,
		gitbe.DefaultDbPath), "politeiad database directory")
)

func _main() error {
	flag.Parse()

	// Initialize global filesystem lock.  The lock is in the parent
	// directory of the database.
	parentDir := filepath.Clean(filepath.Join(*dbDirectory, ".."))
	lockFilename := filepath.Join(parentDir, gitbe.LockFilename)
	var err error
	lock, err := lockfile.New(lockFilename, 100*time.Millisecond)
	if err != nil {
		return err
	}
	err = lock.Lock(gitbe.LockDuration)
	if err != nil {
		return err
	}
	defer func() {
		err := lock.Unlock()
		if err != nil {
			fmt.Fprintf(os.Stderr, "New unlock error: %v", err)
		}
	}()

	fmt.Printf("Database: %v\n", *dbDirectory)
	fmt.Printf("Lockfile: %v\n", lockFilename)

	if _, err = os.Stat(*dbDirectory); os.IsNotExist(err) {
		return fmt.Errorf("Database directory does not exist: %v",
			*dbDirectory)
	}
	db, err := leveldb.OpenFile(*dbDirectory, &opt.Options{
		ErrorIfMissing: true,
	})
	if err != nil {
		return err
	}
	i := db.NewIterator(nil, nil)
	for i.Next() {
		fmt.Printf("%v\n", strings.Repeat("=", 80))
		key := i.Key()
		value := i.Value()
		var (
			k string
			v interface{}
		)
		if string(key) == gitbe.VersionKey {
			version, err := gitbe.DecodeVersion(value)
			if err != nil {
				return err
			}
			k = gitbe.VersionKey
			v = version
		} else if string(key) == gitbe.LastAnchorKey {
			lastAnchor, err := gitbe.DecodeLastAnchor(value)
			if err != nil {
				return err
			}
			k = gitbe.LastAnchorKey
			v = lastAnchor
		} else if string(key) == gitbe.UnconfirmedKey {
			ua, err := gitbe.DecodeUnconfirmedAnchor(value)
			if err != nil {
				return err
			}
			k = gitbe.UnconfirmedKey
			v = ua
		} else {
			anchor, err := gitbe.DecodeAnchor(value)
			if err != nil {
				return err
			}
			k = hex.EncodeToString(key)
			v = anchor

		}
		fmt.Printf("key     : %v\n", k)
		fmt.Printf("Record  : %v", spew.Sdump(v))
	}
	i.Release()
	return i.Error()
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
