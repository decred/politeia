// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"testing"
	"time"

	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/pquerna/otp/totp"
)

func TestProcessSetTOTP(t *testing.T) {
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	basicUser, _ := newUser(t, p, true, false)

	alreadySetUser, _ := newUser(t, p, true, false)

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      defaultPoliteiaIssuer,
		AccountName: alreadySetUser.Username,
	})
	if err != nil {
		t.Errorf("unable to generate secret key %v", err)
	}

	alreadySetUser.TOTPType = int(www.TOTPTypeBasic)
	alreadySetUser.TOTPSecret = key.Secret()
	alreadySetUser.TOTPVerified = true
	alreadySetUser.TOTPLastUpdated = append(alreadySetUser.TOTPLastUpdated, time.Now().Unix())

	err = p.db.UserUpdate(*alreadySetUser)
	if err != nil {
		t.Errorf("unable to update user secret key %v", err)
	}

	code, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Errorf("unable to generate code %v", err)
	}
	var tests = []struct {
		name      string
		params    www.SetTOTP
		wantError error
		user      *user.User
	}{
		{
			"error wrong type",
			www.SetTOTP{
				Type: www.TOTPTypeInvalid,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusTOTPInvalidType,
			},
			basicUser,
		},
		{
			"success",
			www.SetTOTP{
				Type: www.TOTPTypeBasic,
			},
			nil,
			basicUser,
		},
		{
			"error already set wrong code",
			www.SetTOTP{
				Type: www.TOTPTypeBasic,
				Code: "12345",
			},
			www.UserError{
				ErrorCode: www.ErrorStatusTOTPFailedValidation,
			},
			alreadySetUser,
		},
		{
			"success already set",
			www.SetTOTP{
				Type: www.TOTPTypeBasic,
				Code: code,
			},
			nil,
			alreadySetUser,
		},
	}

	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			reply, err := p.processSetTOTP(v.params, v.user)
			if err != nil {
				got := errToStr(err)
				want := errToStr(v.wantError)
				if got != want {
					t.Errorf("got %v, want %v", got, want)
				}
				return
			}
			userInfo, err := p.userByIDStr(v.user.ID.String())
			if err != nil {
				t.Errorf("unable to get update user %v", err)
			}
			if userInfo.TOTPSecret != reply.Key {
				t.Error("secret returned does not match saved key")
			}
		})
	}
}

func TestProcessVerifyTOTP(t *testing.T) {
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	usr, _ := newUser(t, p, true, false)

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      defaultPoliteiaIssuer,
		AccountName: usr.Username,
	})
	if err != nil {
		t.Errorf("unable to generate secret key %v", err)
	}

	usr.TOTPType = int(www.TOTPTypeBasic)
	usr.TOTPSecret = key.Secret()
	usr.TOTPVerified = false
	usr.TOTPLastUpdated = append(usr.TOTPLastUpdated, time.Now().Unix())

	err = p.db.UserUpdate(*usr)
	if err != nil {
		t.Errorf("unable to update user secret key %v", err)
	}

	code, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Errorf("unable to generate code %v", err)
	}

	var tests = []struct {
		name      string
		params    www.VerifyTOTP
		wantError error
	}{
		{
			"error wrong code",
			www.VerifyTOTP{
				Code: "12345",
			},
			www.UserError{
				ErrorCode: www.ErrorStatusTOTPFailedValidation,
			},
		},
		{
			"success",
			www.VerifyTOTP{
				Code: code,
			},
			nil,
		},
	}

	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			_, err := p.processVerifyTOTP(v.params, usr)
			if err != nil {
				got := errToStr(err)
				want := errToStr(v.wantError)
				if got != want {
					t.Errorf("got %v, want %v", got, want)
				}
				return
			}
		})
	}
}
