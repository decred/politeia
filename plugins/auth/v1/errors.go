// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

type ErrCode uint32

const (
	ErrCodeInvalid            ErrCode = 0
	ErrCodeNotAuthorized      ErrCode = 1
	ErrCodeInvalidPayload     ErrCode = 2
	ErrCodeInvalidUsername    ErrCode = 3
	ErrCodeInvalidPassword    ErrCode = 4
	ErrCodeInvalidContactInfo ErrCode = 5
)

// ErrCodes contains the human readable error string for the error codes.
var ErrCodes = map[ErrCode]string{
	ErrCodeInvalid:            "invalid error code",
	ErrCodeNotAuthorized:      "not authorized",
	ErrCodeInvalidPayload:     "invalid payload",
	ErrCodeInvalidUsername:    "invalid username",
	ErrCodeInvalidPassword:    "invalid password",
	ErrCodeInvalidContactInfo: "invalid contact info",
}
