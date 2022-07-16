// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

const (
	PluginID             = "auth"
	PluginVersion uint32 = 1
)

const (
	CmdNewUser = "newuser"
)

const (
	PermPublic = "public"
	PermUser   = "user"
	PermAdmin  = "admin"
)

type ErrCode uint32

const (
	ErrCodeInvalid       ErrCode = 0
	ErrCodeNotAuthorized ErrCode = 1
)
