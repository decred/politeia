// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

// Everything defined in this file is a temporary measure until proper user
// plugins have been added to politeiawww, at which point these errors will be
// deprecated.

const (
	// UserPluginID is a temporary plugin ID for user functionality
	// that is specific to pi.
	UserPluginID = "piuser"

	// ErrorCodeInvalid is an invalid error code.
	ErrorCodeInvalid = 0

	// ErrorCodeUserRegistrationNotPaid is returned when a user
	// attempts to write data to politeia prior to paying their user
	// registration fee.
	ErrorCodeUserRegistrationNotPaid = 1

	// ErrorCodeBalanceInsufficient is returned when a user attempts
	// to submit a proposal but does not have a proposal credit.
	ErrorCodeUserBalanceInsufficient = 2
)

var (
	// ErrorCodes contains the human readable error codes.
	ErrorCodes = map[int]string{
		ErrorCodeInvalid:                 "error code invalid",
		ErrorCodeUserRegistrationNotPaid: "user registration not paid",
		ErrorCodeUserBalanceInsufficient: "user balance insufficient",
	}
)
