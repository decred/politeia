// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

import "fmt"

// UserErr represents an error that occured during the execution of a plugin
// command and that was caused by the user.
type UserErr struct {
	ErrCode    uint32
	ErrContext string
}

// Error satisfies the error interface.
func (e UserErr) Error() string {
	if e.ErrContext == "" {
		return fmt.Sprintf("app user err: %v", e.ErrCode)
	}
	return fmt.Sprintf("app user err: %v - %v", e.ErrCode, e.ErrContext)
}
