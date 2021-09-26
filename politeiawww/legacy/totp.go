// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package legacy

import (
	"fmt"
	"time"

	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const (
	defaultPoliteiaIssuer = "politeia"
	defaultCMSIssuer      = "cms"

	// Period (in seconds) of TOTP for testing used for generating codes during
	// tests. A low period allows for codes to be generated and tested very
	// quickly.
	totpTestPeriod = 1
)

var (
	validTOTPTypes = map[www.TOTPMethodT]bool{
		www.TOTPTypeBasic: true,
	}
)

func (p *LegacyPoliteiawww) totpGenerateOpts(issuer, accountName string) totp.GenerateOpts {
	if p.test {
		// Set the period a totp code is valid for to 1 second when
		// testing so the unit tests don't take forever.
		return totp.GenerateOpts{
			Issuer:      issuer,
			AccountName: accountName,
			Period:      totpTestPeriod,
		}
	}
	return totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
	}
}

func (p *LegacyPoliteiawww) totpGenerateCode(secret string, t time.Time) (string, error) {
	if p.test {
		// Set the period a totp code is valid for to 1 second when
		// testing so the unit tests don't take forever.
		return totp.GenerateCodeCustom(secret, t, totp.ValidateOpts{
			Period:    totpTestPeriod,
			Skew:      0,
			Digits:    6,
			Algorithm: otp.AlgorithmSHA1,
		})
	}
	return totp.GenerateCode(secret, t)
}

func (p *LegacyPoliteiawww) totpValidate(code, secret string, t time.Time) (bool, error) {
	if p.test {
		// Set the period a totp code is valid for to 1 second when
		// testing so the unit tests don't take forever.
		return totp.ValidateCustom(code, secret, t, totp.ValidateOpts{
			Period:    totpTestPeriod,
			Skew:      0,
			Digits:    6,
			Algorithm: otp.AlgorithmSHA1,
		})
	}
	return totp.Validate(code, secret), nil
}

func (p *LegacyPoliteiawww) totpCheck(code string, u *user.User) error {
	// Return error to alert that a code is required.
	if code == "" {
		log.Debugf("login: totp code required %v", u.Email)
		return www.UserError{
			ErrorCode: www.ErrorStatusRequiresTOTPCode,
		}
	}

	// Get the generated totp code. The provided code must match this
	// generated code.
	requestTime := time.Now()
	currentCode, err := p.totpGenerateCode(u.TOTPSecret, requestTime)
	if err != nil {
		return fmt.Errorf("totpGenerateCode: %v", err)
	}

	// Verify the user does not have too many failed attempts for this
	// epoch.
	if len(u.TOTPLastFailedCodeTime) >= totpFailedAttempts {
		// The user has too many failed attempts. We must first verify
		// that the failed attempts are from this epoch before this is
		// considered to be an error. If the generated code from the
		// failed timestamp matches the generated code from the current
		// timestamp then we know the failures occurred during this epoch.
		failedTS := u.TOTPLastFailedCodeTime[len(u.TOTPLastFailedCodeTime)-1]
		oldCode, err := p.totpGenerateCode(u.TOTPSecret, time.Unix(failedTS, 0))
		if err != nil {
			return fmt.Errorf("totpGenerateCode: %v", err)
		}
		if oldCode == currentCode {
			// The failures occurred in the same epoch which means the user
			// has exceeded their max allowed attempts.
			return www.UserError{
				ErrorCode: www.ErrorStatusTOTPWaitForNewCode,
			}
		}

		// Previous failures are not from this epoch. Clear them out.
		u.TOTPLastFailedCodeTime = []int64{}
	}

	// Verify the provided code matches the generated code
	var replyError error
	if currentCode == code {
		// The code matches. Clear out all previous failed attempts
		// before returning.
		u.TOTPLastFailedCodeTime = []int64{}
	} else {
		// The code doesn't match. Save the failure and return an error.
		ts := requestTime.Unix()
		u.TOTPLastFailedCodeTime = append(u.TOTPLastFailedCodeTime, ts)
		replyError = www.UserError{
			ErrorCode: www.ErrorStatusTOTPFailedValidation,
		}
	}

	// Update the user database
	err = p.db.UserUpdate(*u)
	if err != nil {
		return fmt.Errorf("UserUpdate: %v", err)
	}

	return replyError
}
