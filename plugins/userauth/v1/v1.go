// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

const (
	PluginID = "userauth"
)

type Permission uint64

const (
	PermissionInvalid Permission = 0
	PermissionAdmin   Permission = 1
	PermissionUser    Permission = 2
	PermissionPublic  Permission = 3
)
