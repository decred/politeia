package localdb

import (
	"encoding/binary"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/badoux/checkmail"
	"github.com/decred/politeia/politeiawww/database"
	"github.com/syndtr/goleveldb/leveldb"
)

const (
	UserdbPath    = "users"
	LastUserIdKey = "lastuserid"

	UserVersion    uint32 = 1
	UserVersionKey        = "userversion"

	NotificationPrefixKey    = "notifications-"
	MaxNumberOfNotifications = 10
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

// isUserRecord returns true if the given key is a user record,
// and false otherwise. This is helpful when iterating the user records
// because the DB contains some non-user records.
func isUserRecord(key string) bool {
	return key != UserVersionKey && key != LastUserIdKey && !strings.HasPrefix(key, NotificationPrefixKey)
}

// getUserNotificationsKey generates the key to access the notifications for
// a given user email.
func getUserNotificationsKey(email string) []byte {
	return []byte(NotificationPrefixKey + email)
}

// addNotification updates the user notifications by keeping it's length lower
// or equal to the maximum number notifications per user.
func addNotification(n database.Notification, ns []database.Notification, max int) []database.Notification {
	// find the biggest Id
	maxid := uint64(0)
	for _, v := range ns {
		if v.ID > maxid {
			maxid = v.ID
		}
	}
	n.ID = maxid + 1
	// if the notifications length is under the max number, just append it
	if len(ns) < max {
		return append(ns, n)
	}

	// otherwise, remove the remaining elements and add the new notification
	idx := (len(ns) - max) + 1
	newNs := ns[idx:]
	return append(newNs, n)
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

// UserGetByUsername returns a user record given its username, if found in the database.
//
// UserGetByUsername satisfies the backend interface.
func (l *localdb) UserGetByUsername(username string) (*database.User, error) {
	l.Lock()
	defer l.Unlock()

	if l.shutdown {
		return nil, database.ErrShutdown
	}

	log.Debugf("UserGetByUsername\n")

	iter := l.userdb.NewIterator(nil, nil)
	for iter.Next() {
		key := iter.Key()
		value := iter.Value()

		if !isUserRecord(string(key)) {
			continue
		}

		user, err := DecodeUser(value)
		if err != nil {
			return nil, err
		}

		if strings.ToLower(user.Username) == strings.ToLower(username) {
			return user, err
		}
	}
	iter.Release()

	return nil, iter.Error()
}

// UserGetById returns a user record given its id, if found in the database.
//
// UserGetById satisfies the backend interface.
func (l *localdb) UserGetById(id uint64) (*database.User, error) {
	l.Lock()
	defer l.Unlock()

	if l.shutdown {
		return nil, database.ErrShutdown
	}

	log.Debugf("UserGetById\n")

	iter := l.userdb.NewIterator(nil, nil)
	for iter.Next() {
		key := iter.Key()
		value := iter.Value()

		if !isUserRecord(string(key)) {
			continue
		}

		user, err := DecodeUser(value)
		if err != nil {
			return nil, err
		}

		if user.ID == id {
			return user, err
		}
	}
	iter.Release()

	return nil, iter.Error()
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

		if !isUserRecord(string(key)) {
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

// NotificationNew adds a notification into a user's mailbox
func (l *localdb) NotificationNew(n database.Notification, email string) error {
	l.Lock()
	defer l.Unlock()

	if l.shutdown {
		return database.ErrShutdown
	}

	log.Debugf("NotificationNew\n")

	// Make sure user exists
	exists, err := l.userdb.Has([]byte(email), nil)
	if err != nil {
		return err
	} else if !exists {
		return database.ErrUserNotFound
	}

	key := getUserNotificationsKey(email)
	var notifications []database.Notification

	n.Viewed = false
	n.Timestamp = time.Now().Unix()
	// Check if the user has already a mailbox registered
	exists, err = l.userdb.Has(key, nil)
	if err != nil {
		return err
	}
	if exists {
		payload, err := l.userdb.Get(key, nil)
		if err != nil {
			return err
		}

		ns, err := DecodeNotifications(payload)
		if err != nil {
			return err
		}
		notifications = addNotification(n, *ns, MaxNumberOfNotifications)
	} else {
		n.ID = 0
		notifications = []database.Notification{n}
	}

	payload, err := EncodeNotifications(notifications)
	if err != nil {
		return err
	}

	return l.userdb.Put(key, payload, nil)
}

// NotificationsGet returns all notifications for a given user
func (l *localdb) NotificationsGet(email string) ([]database.Notification, error) {
	l.Lock()
	defer l.Unlock()

	if l.shutdown {
		return nil, database.ErrShutdown
	}

	log.Debugf("NotificationsGet\n")

	// Make sure user exists
	exists, err := l.userdb.Has([]byte(strings.ToLower(email)), nil)
	if err != nil {
		return nil, err
	} else if !exists {
		return nil, database.ErrUserNotFound
	}

	key := getUserNotificationsKey(email)

	// Check if the user has a mailbox registered
	exists, err = l.userdb.Has(key, nil)
	if err != nil {
		return nil, err
	}
	if !exists {
		// if the mailbox doens't exist return it as empty
		ns := []database.Notification{}
		return ns, nil
	}

	payload, err := l.userdb.Get(key, nil)
	if err != nil {
		return nil, err
	}
	ns, err := DecodeNotifications(payload)
	if err != nil {
		return nil, err
	}

	return *ns, nil
}

// NotificationsUpdate updates one or multiple user notifications
func (l *localdb) NotificationsUpdate(nids []database.Notification, email string) ([]database.Notification, error) {
	l.Lock()
	defer l.Unlock()

	if l.shutdown {
		return nil, database.ErrShutdown
	}

	log.Debugf("NotificationsUpdate\n")

	// Make sure user exists
	exists, err := l.userdb.Has([]byte(email), nil)
	if err != nil {
		return nil, err
	} else if !exists {
		return nil, database.ErrUserNotFound
	}

	key := getUserNotificationsKey(email)

	// Check if the user has a mailbox registered
	exists, err = l.userdb.Has(key, nil)
	if err != nil {
		return nil, err
	}
	if !exists {
		// if the mailbox doens't exist return an error
		return nil, database.ErrUserNotificationsNotFound
	}

	// Get current user notifications
	payload, err := l.userdb.Get(key, nil)
	if err != nil {
		return nil, err
	}
	ns, err := DecodeNotifications(payload)
	if err != nil {
		return nil, err
	}

	// create a map of notifications to be updated
	nu := make(map[uint64]database.Notification)
	for _, n := range nids {
		nu[n.ID] = n
	}

	// Update notifications
	for i, n := range *ns {
		if b, ok := nu[n.ID]; ok {
			(*ns)[i] = b
		}
	}

	payload, err = EncodeNotifications(*ns)
	if err != nil {
		return nil, err
	}

	// update db
	err = l.userdb.Put(key, payload, nil)
	if err != nil {
		return nil, err
	}

	return *ns, nil
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
