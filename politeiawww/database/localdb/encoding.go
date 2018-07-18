package localdb

import (
	"encoding/json"
	"path/filepath"
	"time"

	"github.com/decred/politeia/politeiawww/database"
	"github.com/syndtr/goleveldb/leveldb"
)

// EncodeVersion encodes Version into a JSON byte slice.
func EncodeVersion(version Version) ([]byte, error) {
	b, err := json.Marshal(version)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// DecodeVersion decodes a JSON byte slice into a Version.
func DecodeVersion(payload []byte) (*Version, error) {
	var version Version

	err := json.Unmarshal(payload, &version)
	if err != nil {
		return nil, err
	}

	return &version, nil
}

// openUserDB opens the user database and writes out the version record if
// needed.
func (l *localdb) openUserDB(path string) error {
	// open database
	var err error
	l.userdb, err = leveldb.OpenFile(filepath.Join(l.root, UserdbPath), nil)
	if err != nil {
		return err
	}

	// See if we need to write a version record
	exists, err := l.userdb.Has([]byte(UserVersionKey), nil)
	if err != nil || exists {
		return err
	}

	// Write version record
	v, err := EncodeVersion(Version{
		Version: UserVersion,
		Time:    time.Now().Unix(),
	})
	if err != nil {
		return err
	}
	return l.userdb.Put([]byte(UserVersionKey), v, nil)
}

// EncodeUser encodes User into a JSON byte slice.
func EncodeUser(u database.User) ([]byte, error) {
	b, err := json.Marshal(u)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// DecodeUser decodes a JSON byte slice into a User.
func DecodeUser(payload []byte) (*database.User, error) {
	var u database.User

	err := json.Unmarshal(payload, &u)
	if err != nil {
		return nil, err
	}

	return &u, nil
}

// EncodeNotifications encodes Notification into a JSON byte slice.
func EncodeNotifications(n []database.Notification) ([]byte, error) {
	d, err := json.Marshal(n)
	if err != nil {
		return nil, err
	}

	return d, nil
}

// DecodeNotifications decodes a JSON byte slice into a Notification.
func DecodeNotifications(payload []byte) (*[]database.Notification, error) {
	var n []database.Notification

	err := json.Unmarshal(payload, &n)
	if err != nil {
		return nil, err
	}

	return &n, nil
}
