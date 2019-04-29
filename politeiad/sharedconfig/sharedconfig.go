// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package sharedconfig

import (
	"github.com/decred/dcrd/dcrutil"
)

const (
	DefaultDataDirname = "data"
)

var (
	DefaultHomeDir = dcrutil.AppDataDir("politeiad", false)
)
