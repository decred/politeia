package localdb

import (
	"sync"

	"github.com/decred/politeia/politeiawww/database"

	"github.com/syndtr/goleveldb/leveldb"
)

var (
	_ database.Database = (*localdb)(nil)
)

// localdb implements the database interface.
type localdb struct {
	sync.RWMutex
	db       *leveldb.DB // Database
	shutdown bool        // Backend is shutdown
}

// UserGet returns a user record if found in the database.
//
// UserGet satisfies the backend interface.
func (l *localdb) UserGet(email string) (*database.User, error) {
	return nil, database.ErrUserNotFound
}

// Close shuts down the database.  All interface functions MUST return with
// errShutdown if the backend is shutting down.
//
// Close satisfies the backend interface.
func (l *localdb) Close() {
	l.Lock()
	defer l.Unlock()

	l.shutdown = true
	l.db.Close()
}

// New creates a new localdb instance.
func New() (*localdb, error) {
	l := &localdb{}
	return l, nil
}
