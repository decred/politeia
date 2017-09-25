package localdb

import (
	"encoding/json"
	"path/filepath"
	"time"

	"github.com/decred/politeia/politeiawww/database"
	"github.com/syndtr/goleveldb/leveldb"
)

const (
	UserVersion    uint32 = 1
	UserVersionKey        = "userversion"
)

// Version contains the database version.
type Version struct {
	Version uint32 // Database version
	Time    int64  // Time of record creation
}

// encodeVersion encodes Version into a JSON byte slice.
func encodeVersion(version Version) ([]byte, error) {
	b, err := json.Marshal(version)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// decodeVersion decodes a JSON byte slice into a Version.
func decodeVersion(payload []byte) (*Version, error) {
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
	v, err := encodeVersion(Version{
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
