package localdb

import (
	"encoding/binary"
	"path/filepath"
	"strings"
	"sync"

	"github.com/decred/politeia/politeiawww/user"
	"github.com/google/uuid"
	"github.com/syndtr/goleveldb/leveldb"
)

const (
	UserdbPath              = "users"
	LastPaywallAddressIndex = "lastpaywallindex"

	UserVersion uint32 = 1

	UserVersionKey = "userversion"
)

var (
	_ user.Database = (*localdb)(nil)
)

// localdb implements the Database interface.
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

// isUserRecord returns true if the given key is a user record,
// and false otherwise. This is helpful when iterating the user records
// because the DB contains some non-user records.
func isUserRecord(key string) bool {
	return key != UserVersionKey && key != LastPaywallAddressIndex
}

// Store new user.
//
// UserNew satisfies the Database interface.
func (l *localdb) UserNew(u user.User) error {
	l.Lock()
	defer l.Unlock()

	if l.shutdown {
		return user.ErrShutdown
	}

	log.Debugf("UserNew: %v", u)

	// Make sure user does not exist
	ok, err := l.userdb.Has([]byte(u.Email), nil)
	if err != nil {
		return err
	} else if ok {
		return user.ErrUserExists
	}

	// Fetch the next unique paywall index for the user.
	var lastPaywallIndex uint64
	b, err := l.userdb.Get([]byte(LastPaywallAddressIndex), nil)
	if err != nil {
		if err != leveldb.ErrNotFound {
			return err
		}
	} else {
		lastPaywallIndex = binary.LittleEndian.Uint64(b) + 1
	}

	// Set the new paywall index on the user.
	u.PaywallAddressIndex = lastPaywallIndex

	// Write the new paywall index back to the db.
	b = make([]byte, 8)
	binary.LittleEndian.PutUint64(b, lastPaywallIndex)
	err = l.userdb.Put([]byte(LastPaywallAddressIndex), b, nil)
	if err != nil {
		return err
	}

	// Set unique uuid for the user.
	u.ID = uuid.New()

	payload, err := user.EncodeUser(u)
	if err != nil {
		return err
	}

	return l.userdb.Put([]byte(u.Email), payload, nil)
}

// UserGet returns a user record if found in the database.
//
// UserGet satisfies the Database interface.
func (l *localdb) UserGet(email string) (*user.User, error) {
	l.RLock()
	defer l.RUnlock()

	if l.shutdown {
		return nil, user.ErrShutdown
	}

	payload, err := l.userdb.Get([]byte(strings.ToLower(email)), nil)
	if err == leveldb.ErrNotFound {
		return nil, user.ErrUserNotFound
	} else if err != nil {
		return nil, err
	}

	u, err := user.DecodeUser(payload)
	if err != nil {
		return nil, err
	}

	return u, nil
}

// UserGetByUsername returns a user record given its username, if found in the
// database.
//
// UserGetByUsername satisfies the Database interface.
func (l *localdb) UserGetByUsername(username string) (*user.User, error) {
	l.RLock()
	defer l.RUnlock()

	if l.shutdown {
		return nil, user.ErrShutdown
	}

	log.Debugf("UserGetByUsername")

	iter := l.userdb.NewIterator(nil, nil)
	for iter.Next() {
		key := iter.Key()
		value := iter.Value()

		if !isUserRecord(string(key)) {
			continue
		}

		u, err := user.DecodeUser(value)
		if err != nil {
			return nil, err
		}

		if strings.EqualFold(u.Username, username) {
			return u, err
		}
	}
	iter.Release()

	if iter.Error() != nil {
		return nil, iter.Error()
	}

	return nil, user.ErrUserNotFound
}

// UserGetByPubKey returns a user record given its public key. The public key
// can be any of the public keys in the user's identity history.
//
// UserGetByPubKey satisfies the Database interface.
func (l *localdb) UserGetByPubKey(pubKey string) (*user.User, error) {
	log.Tracef("UserGetByPubKey: %v", pubKey)

	l.RLock()
	defer l.RUnlock()

	if l.shutdown {
		return nil, user.ErrShutdown
	}

	iter := l.userdb.NewIterator(nil, nil)
	for iter.Next() {
		key := iter.Key()
		value := iter.Value()
		if !isUserRecord(string(key)) {
			continue
		}
		u, err := user.DecodeUser(value)
		if err != nil {
			return nil, err
		}
		for _, v := range u.Identities {
			if v.String() == pubKey {
				return u, err
			}
		}
	}
	iter.Release()

	if iter.Error() != nil {
		return nil, iter.Error()
	}

	return nil, user.ErrUserNotFound
}

// UsersGetByPubKey, given a list of public keys, returns a map where the keys
// are a public key and the value is a user record. Public keys can be any of
// the public keys in the user's identity history.
//
// UsersGetByPubKey satisfies the Database interface.
func (l *localdb) UsersGetByPubKey(pubKeys []string) (map[string]user.User, error) {
	log.Tracef("UsersGetByPubKey: %v", pubKeys)

	l.RLock()
	defer l.RUnlock()

	if l.shutdown {
		return nil, user.ErrShutdown
	}

	pubKeyMap := make(map[string]bool)
	for _, v := range pubKeys {
		pubKeyMap[v] = true
	}

	userMap := make(map[string]user.User)

	iter := l.userdb.NewIterator(nil, nil)
	for iter.Next() {
		key := iter.Key()
		value := iter.Value()
		if !isUserRecord(string(key)) {
			continue
		}
		u, err := user.DecodeUser(value)
		if err != nil {
			return nil, err
		}
		for _, v := range u.Identities {
			if _, ok := pubKeyMap[v.String()]; ok {
				userMap[v.String()] = *u
			}
		}
	}
	iter.Release()

	if iter.Error() != nil {
		return nil, iter.Error()
	}

	if len(userMap) != len(pubKeys) {
		return nil, user.ErrUserNotFound
	}

	return userMap, nil
}

// UserGetById returns a user record given its id, if found in the database.
//
// UserGetById satisfies the Database interface.
func (l *localdb) UserGetById(id uuid.UUID) (*user.User, error) {
	l.RLock()
	defer l.RUnlock()

	if l.shutdown {
		return nil, user.ErrShutdown
	}

	log.Debugf("UserGetById")

	iter := l.userdb.NewIterator(nil, nil)
	for iter.Next() {
		key := iter.Key()
		value := iter.Value()

		if !isUserRecord(string(key)) {
			continue
		}

		u, err := user.DecodeUser(value)
		if err != nil {
			return nil, err
		}

		if u.ID == id {
			return u, err
		}
	}
	iter.Release()

	if iter.Error() != nil {
		return nil, iter.Error()
	}

	return nil, user.ErrUserNotFound
}

// Update existing user.
//
// UserUpdate satisfies the Database interface.
func (l *localdb) UserUpdate(u user.User) error {
	l.Lock()
	defer l.Unlock()

	if l.shutdown {
		return user.ErrShutdown
	}

	log.Debugf("UserUpdate: %v", u)

	// Make sure user already exists
	exists, err := l.userdb.Has([]byte(u.Email), nil)
	if err != nil {
		return err
	} else if !exists {
		return user.ErrUserNotFound
	}

	payload, err := user.EncodeUser(u)
	if err != nil {
		return err
	}

	return l.userdb.Put([]byte(u.Email), payload, nil)
}

// Update existing user.
//
// UserUpdate satisfies the Database interface.
func (l *localdb) AllUsers(callbackFn func(u *user.User)) error {
	l.Lock()
	defer l.Unlock()

	if l.shutdown {
		return user.ErrShutdown
	}

	log.Debugf("AllUsers")

	iter := l.userdb.NewIterator(nil, nil)
	for iter.Next() {
		key := iter.Key()
		value := iter.Value()

		if !isUserRecord(string(key)) {
			continue
		}

		u, err := user.DecodeUser(value)
		if err != nil {
			return err
		}

		callbackFn(u)
	}
	iter.Release()

	return iter.Error()
}

// PluginExec executes the provided plugin command.
func (l *localdb) PluginExec(pc user.PluginCommand) (*user.PluginCommandReply, error) {
	return nil, user.ErrInvalidPlugin
}

// RegisterPlugin registers a plugin with the user database.
func (l *localdb) RegisterPlugin(user.Plugin) error {
	return user.ErrInvalidPlugin
}

// Close shuts down the database.  All interface functions MUST return with
// errShutdown if the backend is shutting down.
//
// Close satisfies the Database interface.
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
