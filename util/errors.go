// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package util

import (
	"fmt"

	errs "github.com/pkg/errors"
)

// stackTracer represents the stack trace functionality for an error from
// pkg/errors.
type stackTracer interface {
	StackTrace() errs.StackTrace
}

// StackTrace returns the stack trace for a pkg/errors error. The returned bool
// indicates whether the provided error is a pkg/errors error. Stack traces are
// not available for stdlib errors.
func StackTrace(err error) (string, bool) {
	e, ok := errs.Cause(err).(stackTracer)
	if !ok {
		return "", false
	}
	return fmt.Sprintf("%+v\n", e.StackTrace()), true
}
