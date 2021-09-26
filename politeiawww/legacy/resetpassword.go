// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package legacy

import (
	"encoding/hex"
	"errors"
	"time"

	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/google/uuid"
)

// resetPassword is used to pass the results of the reset password command
// between go routines.
type resetPasswordResult struct {
	reply www.ResetPasswordReply
	err   error
}

func (p *LegacyPoliteiawww) resetPassword(rp www.ResetPassword) resetPasswordResult {
	// Lookup user
	u, err := p.db.UserGetByUsername(rp.Username)
	if err != nil {
		if errors.Is(err, user.ErrUserNotFound) {
			err = www.UserError{
				ErrorCode: www.ErrorStatusUserNotFound,
			}
		}
		return resetPasswordResult{
			err: err,
		}
	}

	// Ensure the provided email address matches the user record
	// email address. If the addresses does't match, return so
	// that the verification token doesn't get sent.
	if rp.Email != u.Email {
		log.Debugf("resetPassword: wrong email: %v %v",
			rp.Email, u.Email)
		return resetPasswordResult{}
	}

	// If the user already has a verification token that has not
	// yet expired, do nothing.
	t := time.Now().Unix()
	if t < u.ResetPasswordVerificationExpiry {
		log.Debugf("resetPassword: unexpired verification token: %v %v",
			t, u.ResetPasswordVerificationExpiry)
		return resetPasswordResult{}
	}

	// The verification token is not present or is present but has expired.

	// Generate a new verification token and expiry.
	tokenb, expiry, err := newVerificationTokenAndExpiry()
	if err != nil {
		return resetPasswordResult{
			err: err,
		}
	}

	// Try to email the verification link first. If it fails, the
	// user record won't be updated in the database.
	recipient := map[uuid.UUID]string{
		u.ID: u.Email,
	}
	err = p.emailUserPasswordReset(rp.Username, hex.EncodeToString(tokenb),
		recipient)
	if err != nil {
		return resetPasswordResult{
			err: err,
		}
	}

	// Update the user record
	u.ResetPasswordVerificationToken = tokenb
	u.ResetPasswordVerificationExpiry = expiry
	err = p.db.UserUpdate(*u)
	if err != nil {
		return resetPasswordResult{
			err: err,
		}
	}

	// Only include the verification token in the reply if the
	// email server has been disabled.
	var reply www.ResetPasswordReply
	if !p.mail.IsEnabled() {
		reply.VerificationToken = hex.EncodeToString(tokenb)
	}

	return resetPasswordResult{
		reply: reply,
	}
}
