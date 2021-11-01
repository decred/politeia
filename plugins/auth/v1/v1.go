// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

const (
	PluginID = "auth"
)

type Permission uint64

const (
	PermissionInvalid Permission = 0
	PermissionRoot    Permission = 1
	PermissionAdmin   Permission = 2
	PermissionUser    Permission = 3
	PermissionPublic  Permission = 4
)
