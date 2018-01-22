package localdb

import (
	"encoding/binary"
	"path/filepath"
	"strings"
	"sync"

	"github.com/decred/politeia/politeiawww/database"

	"github.com/badoux/checkmail"
	"github.com/syndtr/goleveldb/leveldb"
)

const (
	UserdbPath    = "users"
	LastUserIdKey = "lastuserid"

	UserVersion    uint32 = 1
	UserVersionKey        = "userversion"
)

var (
	_ database.Database = (*localdb)(nil)
)

// localdb implements the database interface.
type localdb struct {
	sync.RWMutex
	shutdown bool        // Backend is shutdown
	root     string      // Database root
	userdb   *leveldb.DB // Database context
}

// Version contains the database version.
type Version struct {
	Version uint32 `json:"version"` // Database version
	Time    int64  `json:"time"`    // Time of record creation
}

// Store new user.
//
// UserNew satisfies the backend interface.
func (l *localdb) UserNew(u database.User) error {
	l.Lock()
	defer l.Unlock()

	if l.shutdown {
		return database.ErrShutdown
	}

	log.Debugf("UserNew: %v", u)

	if err := checkmail.ValidateFormat(u.Email); err != nil {
		return database.ErrInvalidEmail
	}

	// Make sure user does not exist
	ok, err := l.userdb.Has([]byte(u.Email), nil)
	if err != nil {
		return err
	} else if ok {
		return database.ErrUserExists
	}

	// Fetch the next unique ID for the user.
	var lastUserId uint64
	b, err := l.userdb.Get([]byte(LastUserIdKey), nil)
	if err != nil {
		if err != leveldb.ErrNotFound {
			return err
		}
	} else {
		lastUserId = binary.LittleEndian.Uint64(b) + 1
	}

	// Set the new id on the user.
	u.ID = lastUserId

	// Write the new id back to the db.
	b = make([]byte, 8)
	binary.LittleEndian.PutUint64(b, lastUserId)
	err = l.userdb.Put([]byte(LastUserIdKey), b, nil)
	if err != nil {
		return err
	}

	payload, err := EncodeUser(u)
	if err != nil {
		return err
	}

	return l.userdb.Put([]byte(u.Email), payload, nil)
}

// UserGet returns a user record if found in the database.
//
// UserGet satisfies the backend interface.
func (l *localdb) UserGet(email string) (*database.User, error) {
	l.Lock()
	defer l.Unlock()

	if l.shutdown {
		return nil, database.ErrShutdown
	}

	log.Debugf("UserGet: %v", email)
	payload, err := l.userdb.Get([]byte(strings.ToLower(email)), nil)
	if err == leveldb.ErrNotFound {
		return nil, database.ErrUserNotFound
	} else if err != nil {
		return nil, err
	}

	u, err := DecodeUser(payload)
	if err != nil {
		return nil, err
	}

	return u, nil
}

// Update existing user.
//
// UserUpdate satisfies the backend interface.
func (l *localdb) UserUpdate(u database.User) error {
	l.Lock()
	defer l.Unlock()

	if l.shutdown {
		return database.ErrShutdown
	}

	log.Debugf("UserUpdate: %v", u)

	// Make sure user already exists
	exists, err := l.userdb.Has([]byte(u.Email), nil)
	if err != nil {
		return err
	} else if !exists {
		return database.ErrUserNotFound
	}

	payload, err := EncodeUser(u)
	if err != nil {
		return err
	}

	return l.userdb.Put([]byte(u.Email), payload, nil)
}

// Update existing user.
//
// UserUpdate satisfies the backend interface.
func (l *localdb) AllUsers(callbackFn func(u *database.User)) error {
	l.Lock()
	defer l.Unlock()

	if l.shutdown {
		return database.ErrShutdown
	}

	log.Debugf("AllUsers\n")

	iter := l.userdb.NewIterator(nil, nil)
	for iter.Next() {
		key := iter.Key()
		value := iter.Value()

		// Ignore the userversion and lastuserid records.
		if string(key) == UserVersionKey || string(key) == LastUserIdKey {
			continue
		}

		u, err := DecodeUser(value)
		if err != nil {
			return err
		}

		callbackFn(u)
	}
	iter.Release()

	return iter.Error()
}

// Close shuts down the database.  All interface functions MUST return with
// errShutdown if the backend is shutting down.
//
// Close satisfies the backend interface.
func (l *localdb) Close() error {
	l.Lock()
	defer l.Unlock()

	l.shutdown = true
	return l.userdb.Close()
}

// New creates a new localdb instance.
func New(root string) (*localdb, error) {
	log.Tracef("localdb New: %v", root)

	l := &localdb{
		root: root,
	}
	err := l.openUserDB(filepath.Join(l.root, UserdbPath))
	if err != nil {
		return nil, err
	}

	return l, nil
}
