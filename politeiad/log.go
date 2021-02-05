// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/decred/politeia/politeiad/backend/gitbe"
	"github.com/decred/politeia/politeiad/backend/tlogbe"
	"github.com/decred/politeia/politeiad/backend/tlogbe/plugins/comments"
	"github.com/decred/politeia/politeiad/backend/tlogbe/plugins/dcrdata"
	"github.com/decred/politeia/politeiad/backend/tlogbe/plugins/ticketvote"
	"github.com/decred/politeia/politeiad/backend/tlogbe/plugins/user"
	"github.com/decred/politeia/politeiad/backend/tlogbe/store/filesystem"
	"github.com/decred/politeia/politeiad/backend/tlogbe/tlog"
	"github.com/decred/politeia/wsdcrdata"
	"github.com/decred/slog"
	"github.com/jrick/logrotate/rotator"
)

// logWriter implements an io.Writer that outputs to both standard output and
// the write-end pipe of an initialized log rotator.
type logWriter struct{}

func (logWriter) Write(p []byte) (n int, err error) {
	os.Stdout.Write(p)
	return logRotator.Write(p)
}

// Loggers per subsystem.  A single backend logger is created and all subsytem
// loggers created from it will write to the backend.  When adding new
// subsystems, add the subsystem logger variable here and to the
// subsystemLoggers map.
//
// Loggers can not be used before the log rotator has been initialized with a
// log file.  This must be performed early during application startup by calling
// initLogRotator.
var (
	// backendLog is the logging backend used to create all subsystem loggers.
	// The backend must not be used before the log rotator has been initialized,
	// or data races and/or nil pointer dereferences will occur.
	backendLog = slog.NewBackend(logWriter{})

	// logRotator is one of the logging outputs.  It should be closed on
	// application shutdown.
	logRotator *rotator.Rotator

	log           = backendLog.Logger("POLI")
	gitbeLog      = backendLog.Logger("GITB")
	tlogbeLog     = backendLog.Logger("BACK")
	tlogLog       = backendLog.Logger("TLOG")
	wsdcrdataLog  = backendLog.Logger("WSDD")
	commentsLog   = backendLog.Logger("COMT")
	dcrdataLog    = backendLog.Logger("DCDA")
	ticketvoteLog = backendLog.Logger("TICK")
	userLog       = backendLog.Logger("USER")
)

// Initialize package-global logger variables.
func init() {
	gitbe.UseLogger(gitbeLog)
	tlogbe.UseLogger(tlogbeLog)
	tlog.UseLogger(tlogLog)
	filesystem.UseLogger(tlogLog)
	wsdcrdata.UseLogger(wsdcrdataLog)
	comments.UseLogger(commentsLog)
	dcrdata.UseLogger(dcrdataLog)
	ticketvote.UseLogger(ticketvoteLog)
	user.UseLogger(userLog)
}

// subsystemLoggers maps each subsystem identifier to its associated logger.
var subsystemLoggers = map[string]slog.Logger{
	"POLI": log,
	"GITB": gitbeLog,
	"BACK": tlogbeLog,
	"TLOG": tlogLog,
	"WSDD": wsdcrdataLog,
	"COMT": commentsLog,
	"DCDA": dcrdataLog,
	"TICK": ticketvoteLog,
	"USER": userLog,
}

// initLogRotator initializes the logging rotater to write logs to logFile and
// create roll files in the same directory.  It must be called before the
// package-global log rotater variables are used.
func initLogRotator(logFile string) {
	logDir, _ := filepath.Split(logFile)
	err := os.MkdirAll(logDir, 0700)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create log directory: %v\n", err)
		os.Exit(1)
	}
	r, err := rotator.New(logFile, 10*1024, false, 3)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create file rotator: %v\n", err)
		os.Exit(1)
	}

	logRotator = r
}

// setLogLevel sets the logging level for provided subsystem.  Invalid
// subsystems are ignored.  Uninitialized subsystems are dynamically created as
// needed.
func setLogLevel(subsystemID string, logLevel string) {
	// Ignore invalid subsystems.
	logger, ok := subsystemLoggers[subsystemID]
	if !ok {
		return
	}

	// Defaults to info if the log level is invalid.
	level, _ := slog.LevelFromString(logLevel)
	logger.SetLevel(level)
}

// setLogLevels sets the log level for all subsystem loggers to the passed
// level.  It also dynamically creates the subsystem loggers as needed, so it
// can be used to initialize the logging system.
func setLogLevels(logLevel string) {
	// Configure all sub-systems with the new logging level.  Dynamically
	// create loggers as needed.
	for subsystemID := range subsystemLoggers {
		setLogLevel(subsystemID, logLevel)
	}
}

// LogClosure is a closure that can be printed with %v to be used to
// generate expensive-to-create data for a detailed log level and avoid doing
// the work if the data isn't printed.
type logClosure func() string

func (c logClosure) String() string {
	return c()
}

func newLogClosure(c func() string) logClosure {
	return logClosure(c)
}
