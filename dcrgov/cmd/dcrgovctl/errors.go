// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/pkg/errors"
)

// stackTracer represents the stack trace functionality for an error from
// pkg/errors.
type stackTracer interface {
	StackTrace() errors.StackTrace
}

// StackTrace returns the stack trace for a pkg/errors error. The returned bool
// indicates whether the provided error is a pkg/errors error. Stack traces are
// not available for stdlib errors.
func stackTrace(err error) (string, bool) {
	e, ok := errors.Cause(err).(stackTracer)
	if !ok {
		return "", false
	}
	return fmt.Sprintf("%+v\n", e.StackTrace()), true
}
