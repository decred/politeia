// Copyright (c) 2017-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"os"
	"path/filepath"

	cmsdb "github.com/decred/politeia/politeiawww/cmsdatabase/cockroachdb"
	"github.com/decred/politeia/politeiawww/codetracker/github"
	ghdb "github.com/decred/politeia/politeiawww/codetracker/github/database/cockroachdb"
	"github.com/decred/politeia/politeiawww/comments"
	"github.com/decred/politeia/politeiawww/events"
	"github.com/decred/politeia/politeiawww/mail"
	"github.com/decred/politeia/politeiawww/pi"
	"github.com/decred/politeia/politeiawww/records"
	"github.com/decred/politeia/politeiawww/sessions"
	"github.com/decred/politeia/politeiawww/ticketvote"
	"github.com/decred/politeia/politeiawww/user/cockroachdb"
	"github.com/decred/politeia/politeiawww/user/localdb"
	"github.com/decred/politeia/politeiawww/user/mysql"
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

	log         = backendLog.Logger("PWWW")
	userdbLog   = backendLog.Logger("USER")
	sessionsLog = backendLog.Logger("SESS")
	eventsLog   = backendLog.Logger("EVNT")
	apiLog      = backendLog.Logger("APIS")

	// CMS loggers
	cmsdbLog         = backendLog.Logger("CMDB")
	wsdcrdataLog     = backendLog.Logger("WSDD")
	githubTrackerLog = backendLog.Logger("GHTR")
	githubdbLog      = backendLog.Logger("GHDB")
)

// Initialize package-global logger variables.
func init() {
	mail.UseLogger(log)
	sessions.UseLogger(sessionsLog)
	events.UseLogger(eventsLog)

	// UserDB loggers
	localdb.UseLogger(userdbLog)
	cockroachdb.UseLogger(userdbLog)
	mysql.UseLogger(userdbLog)

	// API loggers
	records.UseLogger(apiLog)
	comments.UseLogger(apiLog)
	ticketvote.UseLogger(apiLog)
	pi.UseLogger(apiLog)

	// CMS loggers
	cmsdb.UseLogger(cmsdbLog)
	wsdcrdata.UseLogger(wsdcrdataLog)
	github.UseLogger(githubTrackerLog)
	ghdb.UseLogger(githubdbLog)
}

// subsystemLoggers maps each subsystem identifier to its associated logger.
var subsystemLoggers = map[string]slog.Logger{
	"PWWW": log,
	"SESS": sessionsLog,
	"EVNT": eventsLog,
	"USER": userdbLog,
	"APIS": apiLog,
	"CMDB": cmsdbLog,
	"WSDD": wsdcrdataLog,
	"GHTR": githubTrackerLog,
	"GHDB": githubdbLog,
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
