// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"testing"
	"time"

	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/util"
)

func TestInviteNewUser(t *testing.T) {
	p, cleanup := newTestCMSwww(t)
	defer cleanup()

	emailVerified := "test1@example.org"
	inviteUserReq := cms.InviteNewUser{
		Email:     emailVerified,
		Temporary: false,
	}
	reply, err := p.processInviteNewUser(inviteUserReq)
	if err != nil {
		t.Fatalf("error inviting user %v", err)
	}

	id, err := shared.NewIdentity()
	if err != nil {
		t.Fatalf("error another generating identity")
	}
	registerReq := cms.RegisterUser{
		Email:             emailVerified,
		Username:          "test1",
		Password:          "password",
		VerificationToken: reply.VerificationToken,
		PublicKey:         hex.EncodeToString(id.Public.Key[:]),
	}
	_, err = p.processRegisterUser(registerReq)
	if err != nil {
		t.Fatalf("error registering user %v", err)
	}

	emailFreshToken := "test2@example.org"
	inviteUserReq = cms.InviteNewUser{
		Email:     emailFreshToken,
		Temporary: false,
	}
	replyFresh, err := p.processInviteNewUser(inviteUserReq)
	if err != nil {
		t.Fatalf("error inviting user %v", err)
	}

	var tests = []struct {
		name       string
		email      string
		wantError  error
		tokenEmpty bool
		tokenFresh bool
	}{
		{
			"success",
			"test@example.com",
			nil,
			false,
			false,
		},
		{
			"success new token",
			emailFreshToken,
			nil,
			false,
			true,
		},
		{
			"success already verified",
			emailVerified,
			nil,
			true,
			false,
		},
		{
			"error malformed",
			"testemailmalformed",
			www.UserError{
				ErrorCode: www.ErrorStatusMalformedEmail,
			},
			false,
			false,
		},
	}

	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			inviteUserReq := cms.InviteNewUser{
				Email:     v.email,
				Temporary: false,
			}
			replyInvite, err := p.processInviteNewUser(inviteUserReq)

			got := errToStr(err)
			want := errToStr(v.wantError)
			if got != want {
				t.Errorf("got error %v, want %v", got, want)
				return
			}
			// exit tests if err was received since error matched as expected
			if err != nil {
				return
			}
			if replyInvite == nil {
				t.Errorf("invite reply should not be nil here")
				return
			}
			if v.tokenEmpty && len(replyInvite.VerificationToken) > 0 {
				// If token is expected to be empty
				t.Errorf("expecting an empty verification token but got %v",
					replyInvite.VerificationToken)
			}
			if !v.tokenEmpty && len(replyInvite.VerificationToken) == 0 {
				// If token is expected to be non-empty
				t.Errorf("expecting an non-empty verification token but got empty")
			}
			if v.tokenFresh &&
				replyInvite.VerificationToken == replyFresh.VerificationToken {
				// If token is expected to be fresh from one previously received
				t.Errorf("expecting fresh token but got the same")
			}
		})
	}

	emailFirst := "testtemp1@example.org"

	emailSecond := "testtemp2@example.org"

	var testsTempInvite = []struct {
		name                   string
		email                  string
		temp                   bool
		expectedContractorType cms.ContractorTypeT
	}{
		{
			"success",
			emailFirst,
			false,
			cms.ContractorTypeNominee,
		},
		{
			"success temp",
			emailSecond,
			true,
			cms.ContractorTypeTemp,
		},
	}

	for _, v := range testsTempInvite {
		t.Run(v.name, func(t *testing.T) {
			inviteUserReq := cms.InviteNewUser{
				Email:     v.email,
				Temporary: v.temp,
			}
			_, err := p.processInviteNewUser(inviteUserReq)
			if err != nil {
				t.Errorf("error inviting user %v %v", v.email, err)
				return
			}
			u, err := p.userByEmail(v.email)
			if err != nil {
				t.Errorf("error getting user by email %v %v", v.email, err)
				return
			}

			cmsUser, err := p.getCMSUserByID(u.ID.String())
			if err != nil {
				t.Errorf("error getting cms user by id %v %v", u.ID.String(),
					err)
				return
			}

			if cmsUser.ContractorType != v.expectedContractorType {
				t.Errorf("unexpected contractor type got %v, want %v",
					cmsUser.ContractorType, v.expectedContractorType)
			}
		})
	}
}

func TestRegisterUser(t *testing.T) {
	p, cleanup := newTestCMSwww(t)
	defer cleanup()

	// Create user identity and save it to disk
	id, err := shared.NewIdentity()
	if err != nil {
		t.Fatalf("error generating identity")
	}

	email := "test1@example.org"
	username := "test1"
	pwd := "password1"

	inviteUserReq := cms.InviteNewUser{
		Email:     email,
		Temporary: false,
	}
	reply, err := p.processInviteNewUser(inviteUserReq)
	if err != nil {
		t.Fatalf("error inviting user %v", err)
	}

	// Create another user identity and save it to disk
	idFresh, err := shared.NewIdentity()
	if err != nil {
		t.Fatalf("error another generating identity")
	}
	emailFresh := "test2@example.org"
	usernameFresh := "test2"

	inviteUserReqFresh := cms.InviteNewUser{
		Email:     emailFresh,
		Temporary: false,
	}
	replyFresh, err := p.processInviteNewUser(inviteUserReqFresh)
	if err != nil {
		t.Fatalf("error inviting user %v", err)
	}

	usernameTooShort := "a"
	usernameTooLong := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	usernameRegExp := "?blahg!"

	passwordTooShort := "a"

	usernameExpired := "test3"
	emailExpired := "test3@example.org"
	tokenb, err := util.Random(www.VerificationTokenSize)
	if err != nil {
		t.Fatalf("unable to generate verification token %v", err)
	}
	d := time.Duration(www.VerificationExpiryHours) * time.Hour
	expiry := time.Now().Add(-1 * d).Unix()

	idExpired, err := shared.NewIdentity()
	if err != nil {
		t.Fatalf("error another generating identity")
	}

	// Create a new User record
	u := user.User{
		Email:                     emailExpired,
		Username:                  emailExpired,
		NewUserVerificationToken:  tokenb,
		NewUserVerificationExpiry: expiry,
	}
	err = p.db.UserNew(u)
	if err != nil {
		t.Fatalf("error creating expired token user %v", err)
	}

	usr, err := p.db.UserGetByUsername(u.Username)
	if err != nil {
		t.Fatalf("error getting user by username %v", err)
	}
	p.setUserEmailsCache(usr.Email, usr.ID)
	var tests = []struct {
		name      string
		email     string
		username  string
		pwd       string
		token     string
		wantError error
		pubkey    string
	}{
		{
			"success",
			email,
			username,
			pwd,
			reply.VerificationToken,
			nil,
			hex.EncodeToString(id.Public.Key[:]),
		},
		{
			"error expired verification token",
			emailExpired,
			usernameExpired,
			pwd,
			hex.EncodeToString(tokenb),
			www.UserError{
				ErrorCode: www.ErrorStatusVerificationTokenExpired,
			},
			hex.EncodeToString(idExpired.Public.Key[:]),
		},
		{
			"error invalid verification",
			emailFresh,
			usernameFresh,
			pwd,
			"123456",
			www.UserError{
				ErrorCode: www.ErrorStatusVerificationTokenInvalid,
			},
			hex.EncodeToString(idFresh.Public.Key[:]),
		},
		{
			"error wrong verification",
			emailFresh,
			usernameFresh,
			pwd,
			"this is an invalid verification token",
			www.UserError{
				ErrorCode: www.ErrorStatusVerificationTokenInvalid,
			},
			hex.EncodeToString(idFresh.Public.Key[:]),
		},
		{
			"error duplicate pubkey",
			emailFresh,
			usernameFresh,
			pwd,
			replyFresh.VerificationToken,
			www.UserError{
				ErrorCode: www.ErrorStatusDuplicatePublicKey,
			},
			hex.EncodeToString(id.Public.Key[:]),
		},
		{
			"error invalid pubkey",
			emailFresh,
			usernameFresh,
			pwd,
			replyFresh.VerificationToken,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidPublicKey,
			},
			"this is a bad pubkey",
		},
		{
			"error duplicate username",
			emailFresh,
			username,
			pwd,
			"12345",
			www.UserError{
				ErrorCode: www.ErrorStatusDuplicateUsername,
			},
			hex.EncodeToString(idFresh.Public.Key[:]),
		},
		{
			"error malformed username too short",
			emailFresh,
			usernameTooShort,
			pwd,
			"123456",
			www.UserError{
				ErrorCode: www.ErrorStatusMalformedUsername,
			},
			hex.EncodeToString(idFresh.Public.Key[:]),
		},
		{
			"error malformed username too long",
			emailFresh,
			usernameTooLong,
			pwd,
			"123456",
			www.UserError{
				ErrorCode: www.ErrorStatusMalformedUsername,
			},
			hex.EncodeToString(idFresh.Public.Key[:]),
		},
		{
			"error malformed username reg exp",
			emailFresh,
			usernameRegExp,
			pwd,
			"123456",
			www.UserError{
				ErrorCode: www.ErrorStatusMalformedUsername,
			},
			hex.EncodeToString(idFresh.Public.Key[:]),
		},
		{
			"error malformed password too short",
			emailFresh,
			usernameFresh,
			passwordTooShort,
			"123456",
			www.UserError{
				ErrorCode: www.ErrorStatusMalformedPassword,
			},
			hex.EncodeToString(idFresh.Public.Key[:]),
		},
		{
			"success fresh",
			emailFresh,
			usernameFresh,
			pwd,
			replyFresh.VerificationToken,
			nil,
			hex.EncodeToString(idFresh.Public.Key[:]),
		},
		{
			"error user not found",
			"notfound@example.org",
			"notfound",
			pwd,
			"123456",
			www.UserError{
				ErrorCode: www.ErrorStatusVerificationTokenInvalid,
			},
			hex.EncodeToString(idFresh.Public.Key[:]),
		},
	}

	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			registerReq := cms.RegisterUser{
				Email:             v.email,
				Username:          v.username,
				Password:          v.pwd,
				VerificationToken: v.token,
				PublicKey:         v.pubkey,
			}
			_, err = p.processRegisterUser(registerReq)
			got := errToStr(err)
			want := errToStr(v.wantError)
			if got != want {
				t.Errorf("got error %v, want %v", got, want)
			}
		})
	}
}
