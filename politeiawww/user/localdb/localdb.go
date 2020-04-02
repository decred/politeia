package localdb

import (
	"encoding/binary"
	"path/filepath"
	"strings"
	"sync"

	"github.com/thi4go/politeia/politeiawww/user"
	"github.com/google/uuid"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

const (
	UserdbPath              = "users"
	LastPaywallAddressIndex = "lastpaywallindex"

	UserVersion    uint32 = 1
	UserVersionKey        = "userversion"

	// The key for a user session is sessionPrefix+sessionID
	sessionPrefix = "session:"
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
	return key != UserVersionKey &&
		key != LastPaywallAddressIndex &&
		!strings.HasPrefix(key, sessionPrefix)
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

// UsersGetByPubKey returns a [pubkey]user.User map for the provided public
// keys. Public keys can be any of the public keys in the user's identity
// history. If a user is not found, the map will not include an entry for the
// corresponding public key. It is the responsibility of the caller to ensure
// results are returned for all of the provided public keys.
//
// UsersGetByPubKey satisfies the Database interface.
func (l *localdb) UsersGetByPubKey(pubKeys []string) (map[string]user.User, error) {
	log.Tracef("UsersGetByPubKey: %v", pubKeys)

	l.RLock()
	defer l.RUnlock()

	if l.shutdown {
		return nil, user.ErrShutdown
	}

	// Put provided pubkeys into a map
	pk := make(map[string]struct{}, len(pubKeys))
	for _, v := range pubKeys {
		pk[v] = struct{}{}
	}

	// Iterate through all users checking if any identities
	// (active or old) match any of the provided pubkeys.
	users := make(map[string]user.User, len(pubKeys)) // [pubkey]User
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
			_, ok := pk[v.String()]
			if ok {
				users[v.String()] = *u
			}
		}
	}
	iter.Release()

	if iter.Error() != nil {
		return nil, iter.Error()
	}

	return users, nil
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

// SessionSave saves the given session to the database. New sessions are
// inserted into the database. Existing sessions are updated in the database.
//
// SessionSave satisfies the user.Database interface.
func (l *localdb) SessionSave(s user.Session) error {
	log.Tracef("SessionSave: %v", s)

	l.Lock()
	defer l.Unlock()

	if l.shutdown {
		return user.ErrShutdown
	}

	payload, err := user.EncodeSession(s)
	if err != nil {
		return err
	}

	key := []byte(sessionPrefix + s.ID)
	return l.userdb.Put(key, payload, nil)
}

// SessionGetByID returns a session given its id if present in the database.
//
// SessionGetByID satisfies the user.Database interface.
func (l *localdb) SessionGetByID(sid string) (*user.Session, error) {
	log.Tracef("SessionGetByID: %v", sid)

	l.RLock()
	defer l.RUnlock()

	if l.shutdown {
		return nil, user.ErrShutdown
	}

	payload, err := l.userdb.Get([]byte(sessionPrefix+sid), nil)
	if err == leveldb.ErrNotFound {
		return nil, user.ErrSessionNotFound
	} else if err != nil {
		return nil, err
	}

	us, err := user.DecodeSession(payload)
	if err != nil {
		return nil, err
	}

	return us, nil
}

// SessionDeleteByID deletes the session with the given id.
//
// SessionDeleteByID satisfies the user.Database interface.
func (l *localdb) SessionDeleteByID(sid string) error {
	log.Tracef("SessionDeleteByID: %v", sid)

	l.RLock()
	defer l.RUnlock()

	if l.shutdown {
		return user.ErrShutdown
	}

	err := l.userdb.Delete([]byte(sessionPrefix+sid), nil)
	if err != nil {
		return err
	}

	return nil
}

// SessionsDeleteByUserID deletes all sessions for the given user ID, except
// the session IDs in exemptSessionIDs.
//
// SessionsDeleteByUserID satisfies the Database interface.
func (l *localdb) SessionsDeleteByUserID(uid uuid.UUID, exemptSessionIDs []string) error {
	log.Tracef("SessionsDeleteByUserId %v", uid)

	l.RLock()
	defer l.RUnlock()

	if l.shutdown {
		return user.ErrShutdown
	}

	exempt := make(map[string]struct{}, len(exemptSessionIDs)) // [sessionID]struct{}
	for _, v := range exemptSessionIDs {
		exempt[v] = struct{}{}
	}

	batch := new(leveldb.Batch)
	iter := l.userdb.NewIterator(util.BytesPrefix([]byte(sessionPrefix)), nil)
	for iter.Next() {
		key := iter.Key()
		value := iter.Value()

		s, err := user.DecodeSession(value)
		if err != nil {
			return err
		}

		_, ok := exempt[s.ID]
		if ok {
			continue
		}
		if s.UserID == uid {
			batch.Delete(key)
		}
	}
	iter.Release()

	return l.userdb.Write(batch, nil)
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
