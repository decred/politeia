// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.
package main

import (
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/user"
)

// processSetTOTP attempts to set a new TOTP key based on the given TOTP type.
func (p *politeiawww) processSetTOTP(st www.SetTOTP, user *user.User) (*www.SetTOTPReply, error) {

	return nil, nil
}

// processVerifyTOTP attempts to confirm a newly set TOTP key based on the
// given TOTP type.
func (p *politeiawww) processVerifyTOTP(vt www.VerifyTOTP, user *user.User) (*www.VerifyTOTPReply, error) {

	return nil, nil
}
