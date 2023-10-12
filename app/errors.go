// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package app

import "fmt"

// UserErr represents an error that occurred during the execution of a plugin
// command and that was caused by the user.
type UserErr struct {
	Code    uint32
	Context string
}

// Error satisfies the error interface.
func (e UserErr) Error() string {
	if e.Context == "" {
		return fmt.Sprintf("plugin user err: %v", e.Code)
	}
	return fmt.Sprintf("plugin user err: %v - %v", e.Code, e.Context)
}
