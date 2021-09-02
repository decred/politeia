// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tstorebe

import (
	"fmt"

	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store/localdb"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store/mysql"
	"github.com/pkg/errors"
)

const (
	// DBTypeLevelDB is the config option that sets the backing
	// key-value store to a leveldb instance.
	DBTypeLevelDB = "leveldb"

	// DBTypeMySQL is a config option that sets the backing key-value
	// store to a MySQL instance.
	DBTypeMySQL = "mysql"

	// dbUser contains the username that will be used to connect to
	// the MySQL instance.
	dbUser = "politeiad"
)

// blobKVOpts contains configuration options for a blob key-value store.
type blobKVOpts struct {
	Type string // Database type

	// LevelDB options
	AppDir  string // App home directory
	DataDir string // App data directory

	// MySQL options
	Host     string // MySQL host
	Password string // Password for politeiad user
	Net      string // Active net name
}

// newBlobKV initializes and returns a new BlobKV.
func newBlobKV(opts blobKVOpts) (store.BlobKV, error) {
	var (
		kv  store.BlobKV
		err error
	)
	switch opts.Type {
	case DBTypeLevelDB:
		kv, err = localdb.New(opts.AppDir, opts.DataDir)
		if err != nil {
			return nil, err
		}
	case DBTypeMySQL:
		dbName := fmt.Sprintf("%v_kv", opts.Net)
		kv, err = mysql.New(opts.Host, dbUser, opts.Password, dbName)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.Errorf("invalid db type '%v'", opts.Type)
	}

	return kv, nil
}
