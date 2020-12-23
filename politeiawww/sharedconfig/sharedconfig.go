// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package sharedconfig

import (
	"path/filepath"

	"github.com/decred/dcrd/dcrutil/v3"
)

const (
	// DefaultConfigFilename is the default configuration file name.
	DefaultConfigFilename = "politeiawww.conf"

	// DefaultDataDirname is the default data directory name. The data
	// directory is located in the application home directory.
	DefaultDataDirname = "data"
)

var (
	// DefaultHomeDir points to politeiawww's default home directory.
	DefaultHomeDir = dcrutil.AppDataDir("politeiawww", false)

	// DefaultConfigFile points to politeiawww's default config file
	// path.
	DefaultConfigFile = filepath.Join(DefaultHomeDir, DefaultConfigFilename)

	// DefaultDataDir points to politeiawww's default data directory
	// path.
	DefaultDataDir = filepath.Join(DefaultHomeDir, DefaultDataDirname)
)
