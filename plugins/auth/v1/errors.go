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
	ErrCodeInvalidLogin       ErrCode = 6
	ErrCodeInvalidUserID      ErrCode = 7
	ErrCodeInvalidAction      ErrCode = 8
	ErrCodeInvalidGroup       ErrCode = 9
	ErrCodeAccountLocked      ErrCode = 10
	ErrCodeAccountDeactivated ErrCode = 11
	ErrCodeUserNotFound       ErrCode = 12
)

// ErrCodes contains the human readable error string for the error codes.
var ErrCodes = map[ErrCode]string{
	ErrCodeInvalid:            "invalid error code",
	ErrCodeNotAuthorized:      "not authorized",
	ErrCodeInvalidPayload:     "invalid payload",
	ErrCodeInvalidUsername:    "invalid username",
	ErrCodeInvalidPassword:    "invalid password",
	ErrCodeInvalidContactInfo: "invalid contact info",
	ErrCodeInvalidLogin:       "invalid login credentials",
	ErrCodeInvalidUserID:      "invalid user id",
	ErrCodeInvalidAction:      "invalid action",
	ErrCodeInvalidGroup:       "invalid user group",
	ErrCodeAccountLocked:      "user account has been locked",
	ErrCodeAccountDeactivated: "user account has been deactivated",
	ErrCodeUserNotFound:       "user not found",
}
