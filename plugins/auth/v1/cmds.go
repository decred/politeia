// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

const (
	ID             = "auth"
	Version uint32 = 1
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
