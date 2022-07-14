// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package auth

type auth struct {
	perms map[string]map[string]struct{} // [cmd][permissionLevel]
}

// NewPlugin returns a new auth plugin.
func NewPlugin() *auth {
	return &auth{
		perms: make(map[string]map[string]struct{}, 256),
	}
}
