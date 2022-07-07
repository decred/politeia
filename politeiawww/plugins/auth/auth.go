// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package auth

type auth struct{}

// NewPlugin returns a new auth plugin.
func NewPlugin() *auth {
	return &auth{}
}
