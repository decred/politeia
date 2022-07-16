// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package auth

// user contains the auth plugin user data that is saved to the global user.
type user struct {
	Perms []string
}
