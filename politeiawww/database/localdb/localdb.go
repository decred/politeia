package localdb

import (
	"encoding/binary"
	"path/filepath"
	"sync"

	"github.com/decred/politeia/politeiawww/database"

	"github.com/syndtr/goleveldb/leveldb"
)

const (
	userdbPath      = "users"
	lastUserIDField = "lastuserid"
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

// Store new user.
//
// UserNew satisfies the backend interface.
func (l *localdb) UserNew(u database.User) error {
	l.Lock()
	defer l.Unlock()

	if l.shutdown == true {
		return database.ErrShutdown
	}

	log.Debugf("UserNew: %v", u)

	if u.Email == lastUserIDField {
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
	var lastUserID uint64
	b, err := l.userdb.Get([]byte(lastUserIDField), nil)
	if err != nil {
		if err != leveldb.ErrNotFound {
			return err
		}
	} else {
		lastUserID = binary.LittleEndian.Uint64(b) + 1
	}

	// Set the new id on the user.
	u.ID = lastUserID

	// Write the new id back to the db.
	b = make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(lastUserID))
	l.userdb.Put([]byte(lastUserIDField), b, nil)

	payload, err := encodeUser(u)
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

	if l.shutdown == true {
		return nil, database.ErrShutdown
	}

	log.Debugf("UserGet: %v", email)
	payload, err := l.userdb.Get([]byte(email), nil)
	if err == leveldb.ErrNotFound {
		return nil, database.ErrUserNotFound
	} else if err != nil {
		return nil, err
	}

	u, err := decodeUser(payload)
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

	if l.shutdown == true {
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

	payload, err := encodeUser(u)
	if err != nil {
		return err
	}

	return l.userdb.Put([]byte(u.Email), payload, nil)
}

// Clear drops all data from the database.
func (l *localdb) Clear() error {
	l.Lock()
	defer l.Unlock()

	if l.shutdown == true {
		return database.ErrShutdown
	}

	log.Debugf("Clear")

	batch := new(leveldb.Batch)
	iter := l.userdb.NewIterator(nil, nil)
	for iter.Next() {
		batch.Delete(iter.Key())
	}
	iter.Release()
	if err := iter.Error(); err != nil {
		return err
	}

	if err := l.userdb.Write(batch, nil); err != nil {
		return err
	}

	return nil
}

// Close shuts down the database.  All interface functions MUST return with
// errShutdown if the backend is shutting down.
//
// Close satisfies the backend interface.
func (l *localdb) Close() {
	l.Lock()
	defer l.Unlock()

	l.shutdown = true
	l.userdb.Close()
}

// New creates a new localdb instance.
func New(root string) (*localdb, error) {
	log.Tracef("localdb New: %v", root)

	l := &localdb{
		root: root,
	}
	err := l.openUserDB(filepath.Join(l.root, userdbPath))
	if err != nil {
		return nil, err
	}

	return l, nil
}
