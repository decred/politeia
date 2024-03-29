// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package github

import (
	"github.com/decred/politeia/politeiawww/logger"
	"github.com/decred/slog"
)

var log = slog.Disabled

// UseLogger sets the package-wide logger.  Any calls to this function must be
// made before a server is created and used (it is not concurrent safe).
func UseLogger(logger slog.Logger) {
	log = logger
}

// Initialize the package logger.
func init() {
	UseLogger(logger.NewSubsystem("GHTR"))
}
