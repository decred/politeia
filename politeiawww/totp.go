// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.
package main

import (
	"bytes"
	"encoding/base64"
	"image/png"
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

// processSetTOTP attempts to set a new TOTP key based on the given TOTP type.
func (p *politeiawww) processSetTOTP(st www.SetTOTP, u *user.User) (*www.SetTOTPReply, error) {
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
	if p.cfg.Mode == cmsWWWMode {
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
func (p *politeiawww) processVerifyTOTP(vt www.VerifyTOTP, u *user.User) (*www.VerifyTOTPReply, error) {
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

func (p *politeiawww) totpGenerateOpts(issuer, accountName string) totp.GenerateOpts {
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

func (p *politeiawww) totpGenerateCode(secret string, t time.Time) (string, error) {
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

func (p *politeiawww) totpValidate(code, secret string, t time.Time) (bool, error) {
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
