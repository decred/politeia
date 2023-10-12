// Copyright (c) 2017-2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"

	"github.com/decred/slog"
	"github.com/jrick/logrotate/rotator"
	"github.com/pkg/errors"
)

// logWriter implements an io.Writer that outputs to the write-end pipe of an
// initialized log rotator and can optionally write to stdout as well.
type logWriter struct {
	stdout bool // Write to the log file and stdout
}

var (
	// logPrefix is a regular expression that matches the timestamp and log
	// info that is prefixed onto log lines.
	//
	// Log line    : "2022-07-22 11:23:19.766 [DBG] MAIN: Hello, world!"
	// Regexp match: "2022-07-22 11:23:19.766 [DBG] MAIN: "
	logPrefix = regexp.MustCompile(`^[^\[]+[^:]+: `)
)

func (l logWriter) Write(p []byte) (n int, err error) {
	if l.stdout {
		// Trim the prefix from the log line
		// before printing it to stdout.
		idx := logPrefix.FindIndex(p)
		os.Stdout.Write(p[idx[1]:])
	}
	if logRotator == nil {
		// Log rotater not initialized
		return 0, nil
	}
	return logRotator.Write(p)
}

// Loggers per subsystem.  A single backend logger is created and all subsytem
// loggers created from it will write to the backend. New subsystem loggers can
// be added using the NewSubsystem method.
//
// Loggers can not be used before the log rotator has been initialized with a
// log file. This must be performed early during application startup by
// calling the InitLogRotator method.
var (
	// backendLog is the logging backend used to create all subsystem loggers.
	// The backend must not be used before the log rotator has been initialized,
	// or data races and/or nil pointer dereferences will occur.
	backendLog = slog.NewBackend(logWriter{stdout: true})

	// logRotator is one of the logging outputs. It should be closed on
	// application shutdown.
	logRotator *rotator.Rotator

	// subsystemsLoggers contains all of the subsystem loggers. A new subsystem
	// logger is registered using Register().
	subsystemLoggers = map[string]slog.Logger{}
)

// InitLogRotator initializes the logging rotater to write logs to logFile and
// create roll files in the same directory. It must be called before the
// package-global log rotater variables are used.
func InitLogRotator(logFile string) error {
	logDir, _ := filepath.Split(logFile)
	err := os.MkdirAll(logDir, 0700)
	if err != nil {
		return errors.Errorf("failed to create log dir %v: %v",
			logDir, err)
	}
	r, err := rotator.New(logFile, 10*1024, false, 3)
	if err != nil {
		return errors.Errorf("failed to create log file rotator: %v", err)
	}

	logRotator = r

	return nil
}

// CloseLogRotator closes the log rotator.
func CloseLogRotator() {
	if logRotator != nil {
		logRotator.Close()
	}
}

// NewSubsystemLogger registers and returns a new subsystem logger.
func NewSubsystemLogger(subsystemTag string) slog.Logger {
	l, ok := subsystemLoggers[subsystemTag]
	if ok {
		return l
	}
	l = backendLog.Logger(subsystemTag)
	subsystemLoggers[subsystemTag] = l
	return l
}

// SupportedSubsystems returns a sorted slice of the supported subsystems for
// logging purposes.
func SupportedSubsystems() []string {
	// Convert the subsystemLoggers map keys to a slice
	subsystems := make([]string, 0, len(subsystemLoggers))
	for subsysID := range subsystemLoggers {
		subsystems = append(subsystems, subsysID)
	}

	// Sort the subsytems for stable display
	sort.Strings(subsystems)
	return subsystems
}

// SetLogLevel sets the logging level for provided subsystem. Invalid
// subsystems are ignored. The log level defaults to info if an invalid log
// level is provided.
func SetLogLevel(subsystemID string, logLevel string) {
	// Ignore invalid subsystems
	logger, ok := subsystemLoggers[subsystemID]
	if !ok {
		return
	}

	// Defaults to info if the log level is invalid
	level, _ := slog.LevelFromString(logLevel)
	logger.SetLevel(level)
}

// SetLogLevels sets the log level for all subsystem loggers to the passed
// level. The log level defaults to info if an invalid log level is provided.
func SetLogLevels(logLevel string) {
	// Configure all sub-systems with the new logging level
	for subsystemID := range subsystemLoggers {
		SetLogLevel(subsystemID, logLevel)
	}
}

// LogClosure is a closure that can be printed with %v to be used to generate
// expensive-to-create data for a detailed log level and avoid doing the work
// if the data isn't printed.
type LogClosure func() string

func (c LogClosure) String() string {
	return c()
}

// NewLogClosure returns a new LogClosure
func NewLogClosure(c func() string) LogClosure {
	return LogClosure(c)
}
