package localdb

import (
	"encoding/json"
	"path/filepath"
	"sync"

	"github.com/decred/politeia/politeiawww/database"

	"github.com/syndtr/goleveldb/leveldb"
)

const (
	userdbPath = "users"
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

// encodeUser encodes User into a JSON byte slice.
func encodeUser(u database.User) ([]byte, error) {
	b, err := json.Marshal(u)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// decodeUser decodes a JSON byte slice into a User.
func decodeUser(payload []byte) (*database.User, error) {
	var u database.User

	err := json.Unmarshal(payload, &u)
	if err != nil {
		return nil, err
	}

	return &u, nil
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

	// Make sure user does not exist
	ok, err := l.userdb.Has([]byte(u.Email), nil)
	if err != nil {
		return err
	} else if ok {
		return database.ErrUserExists
	}

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

	var err error
	l.userdb, err = leveldb.OpenFile(filepath.Join(l.root, userdbPath), nil)
	if err != nil {
		return nil, err
	}

	return l, nil
}
