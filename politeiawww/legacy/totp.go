// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package legacy

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image/png"
	"time"

	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/config"
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

// processSetTOTP attempts to set a new TOTP key based on the given TOTP type.
func (p *LegacyPoliteiawww) processSetTOTP(st www.SetTOTP, u *user.User) (*www.SetTOTPReply, error) {
	log.Tracef("processSetTOTP: %v", u.ID.String())
	// if the user already has a TOTP secret set, check the code that was given
	// as well to see if it matches to update.
	if u.TOTPSecret != "" && u.TOTPVerified {
		valid, err := p.totpValidate(st.Code, u.TOTPSecret, time.Now())
		if err != nil {
			log.Debugf("Error valdiating totp code %v", err)
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusTOTPFailedValidation,
			}
		}
		if !valid {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusTOTPFailedValidation,
			}
		}
	}

	// Validate TOTP type that was selected.
	if _, ok := validTOTPTypes[st.Type]; !ok {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusTOTPInvalidType,
		}
	}

	issuer := defaultPoliteiaIssuer
	if p.cfg.Mode == config.CMSWWWMode {
		issuer = defaultCMSIssuer
	}
	opts := p.totpGenerateOpts(issuer, u.Username)
	key, err := totp.Generate(opts)
	if err != nil {
		return nil, err
	}
	// Convert TOTP key into a PNG
	var buf bytes.Buffer
	img, err := key.Image(200, 200)
	if err != nil {
		return nil, err
	}
	png.Encode(&buf, img)

	u.TOTPType = int(st.Type)
	u.TOTPSecret = key.Secret()
	u.TOTPVerified = false
	u.TOTPLastUpdated = append(u.TOTPLastUpdated, time.Now().Unix())

	err = p.db.UserUpdate(*u)
	if err != nil {
		return nil, err
	}

	return &www.SetTOTPReply{
		Key:   key.Secret(),
		Image: base64.StdEncoding.EncodeToString(buf.Bytes()),
	}, nil
}

// processVerifyTOTP attempts to confirm a newly set TOTP key based on the
// given TOTP type.
func (p *LegacyPoliteiawww) processVerifyTOTP(vt www.VerifyTOTP, u *user.User) (*www.VerifyTOTPReply, error) {
	valid, err := p.totpValidate(vt.Code, u.TOTPSecret, time.Now())
	if err != nil {
		log.Debugf("Error valdiating totp code %v", err)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusTOTPFailedValidation,
		}
	}
	if !valid {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusTOTPFailedValidation,
		}
	}

	u.TOTPVerified = true
	u.TOTPLastUpdated = append(u.TOTPLastUpdated, time.Now().Unix())

	err = p.db.UserUpdate(*u)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

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
