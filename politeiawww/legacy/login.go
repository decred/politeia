// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package legacy

import (
	"errors"
	"time"

	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// loginReply is used to pass the results of the login command between go
// routines.
type loginResult struct {
	reply *www.LoginReply
	err   error
}

func (p *LegacyPoliteiawww) login(l www.Login) loginResult {
	// Get user record
	u, err := p.userByEmail(l.Email)
	if err != nil {
		if errors.Is(err, user.ErrUserNotFound) {
			log.Debugf("login: user not found for email '%v'",
				l.Email)
			err = www.UserError{
				ErrorCode: www.ErrorStatusInvalidLogin,
			}
		}
		return loginResult{
			reply: nil,
			err:   err,
		}
	}

	// First check if TOTP is enabled and verified.
	if u.TOTPVerified {
		err := p.totpCheck(l.Code, u)
		if err != nil {
			return loginResult{
				reply: nil,
				err:   err,
			}
		}
	}

	// Verify password
	err = bcrypt.CompareHashAndPassword(u.HashedPassword,
		[]byte(l.Password))
	if err != nil {
		// Wrong password. Update user record with failed attempt.
		log.Debugf("login: wrong password")
		if !userIsLocked(u.FailedLoginAttempts) {
			u.FailedLoginAttempts++
			u.TOTPLastFailedCodeTime = make([]int64, 0, 2)
			err := p.db.UserUpdate(*u)
			if err != nil {
				return loginResult{
					reply: nil,
					err:   err,
				}
			}
			// If the failed attempt puts the user over the limit,
			// send them an email informing them their account is
			// now locked.
			if userIsLocked(u.FailedLoginAttempts) {
				recipient := map[uuid.UUID]string{
					u.ID: u.Email,
				}
				err := p.emailUserAccountLocked(u.Username, recipient)
				if err != nil {
					return loginResult{
						reply: nil,
						err:   err,
					}
				}
			}
		}
		return loginResult{
			reply: nil,
			err: www.UserError{
				ErrorCode: www.ErrorStatusInvalidLogin,
			},
		}
	}

	// Verify user account is in good standing
	if u.NewUserVerificationToken != nil {
		return loginResult{
			reply: nil,
			err: www.UserError{
				ErrorCode: www.ErrorStatusEmailNotVerified,
			},
		}
	}
	if u.Deactivated {
		return loginResult{
			reply: nil,
			err: www.UserError{
				ErrorCode: www.ErrorStatusUserDeactivated,
			},
		}
	}
	if userIsLocked(u.FailedLoginAttempts) {
		return loginResult{
			reply: nil,
			err: www.UserError{
				ErrorCode: www.ErrorStatusUserLocked,
			},
		}
	}

	// Update user record with successful login
	lastLoginTime := u.LastLoginTime
	u.FailedLoginAttempts = 0
	u.LastLoginTime = time.Now().Unix()
	u.TOTPLastFailedCodeTime = make([]int64, 0, 2)
	err = p.db.UserUpdate(*u)
	if err != nil {
		return loginResult{
			reply: nil,
			err:   err,
		}
	}

	reply, err := p.createLoginReply(u, lastLoginTime)
	return loginResult{
		reply: reply,
		err:   err,
	}
}

// createLoginReply creates a login reply.
func (p *LegacyPoliteiawww) createLoginReply(u *user.User, lastLoginTime int64) (*www.LoginReply, error) {
	reply := www.LoginReply{
		IsAdmin:            u.Admin,
		UserID:             u.ID.String(),
		Email:              u.Email,
		Username:           u.Username,
		PublicKey:          u.PublicKey(),
		PaywallAddress:     u.NewUserPaywallAddress,
		PaywallAmount:      u.NewUserPaywallAmount,
		PaywallTxNotBefore: u.NewUserPaywallTxNotBefore,
		PaywallTxID:        u.NewUserPaywallTx,
		ProposalCredits:    uint64(len(u.UnspentProposalCredits)),
		LastLoginTime:      lastLoginTime,
		TOTPVerified:       u.TOTPVerified,
	}

	if !p.userHasPaid(*u) {
		err := p.generateNewUserPaywall(u)
		if err != nil {
			return nil, err
		}

		reply.PaywallAddress = u.NewUserPaywallAddress
		reply.PaywallAmount = u.NewUserPaywallAmount
		reply.PaywallTxNotBefore = u.NewUserPaywallTxNotBefore
	}

	return &reply, nil
}
