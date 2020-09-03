package main

import (
	"encoding/hex"
	"testing"

	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

func TestInviteNewUser(t *testing.T) {
	p, cleanup := newTestCMSwww(t)
	defer cleanup()

	var tests = []struct {
		name      string
		email     string
		wantError error
	}{
		{
			"success",
			"test@example.com",
			nil,
		},
		{
			"error malformed",
			"testemailmalformed",
			www.UserError{
				ErrorCode: www.ErrorStatusMalformedEmail,
			},
		},
	}

	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			inviteUserReq := cms.InviteNewUser{
				Email:     v.email,
				Temporary: false,
			}
			_, err := p.processInviteNewUser(inviteUserReq)

			got := errToStr(err)
			want := errToStr(v.wantError)
			if got != want {
				t.Errorf("got error %v, want %v", got, want)
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

	// Create another user identity and save it to disk
	idFresh, err := shared.NewIdentity()
	if err != nil {
		t.Fatalf("error another generating identity")
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
	var tests = []struct {
		name      string
		username  string
		token     string
		wantError error
		pubkey    string
	}{
		{
			"error bad verification",
			username,
			"12345",
			www.UserError{
				ErrorCode: www.ErrorStatusVerificationTokenInvalid,
			},
			hex.EncodeToString(id.Public.Key[:]),
		},
		{
			"success",
			username,
			reply.VerificationToken,
			nil,
			hex.EncodeToString(id.Public.Key[:]),
		},
		{
			"error duplicate pubkey",
			username,
			"12345",
			www.UserError{
				ErrorCode: www.ErrorStatusDuplicatePublicKey,
			},
			hex.EncodeToString(id.Public.Key[:]),
		},
		{
			"error duplicate username",
			username,
			"12345",
			www.UserError{
				ErrorCode: www.ErrorStatusDuplicateUsername,
			},
			hex.EncodeToString(idFresh.Public.Key[:]),
		},
	}

	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			registerReq := cms.RegisterUser{
				Email:             email,
				Username:          v.username,
				Password:          pwd,
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

func TestPostRegisterUser(t *testing.T) {
	p, cleanup := newTestCMSwww(t)
	defer cleanup()

	// Create user identity and save it to disk
	idFirst, err := shared.NewIdentity()
	if err != nil {
		t.Fatalf("error generating identity")
	}

	emailFirst := "test1@example.org"
	usernameFirst := "test1"
	pwdFirst := "password1"

	// Create user identity and save it to disk
	idSecond, err := shared.NewIdentity()
	if err != nil {
		t.Fatalf("error generating identity")
	}

	emailSecond := "test2@example.org"
	usernameSecond := "test2"
	pwdSecond := "password1"

	var tests = []struct {
		name                   string
		email                  string
		username               string
		pwd                    string
		pubkey                 string
		temp                   bool
		expectedContractorType cms.ContractorTypeT
		wantError              error
	}{
		{
			"success",
			emailFirst,
			usernameFirst,
			pwdFirst,
			hex.EncodeToString(idFirst.Public.Key[:]),
			false,
			cms.ContractorTypeNominee,
			nil,
		},
		{
			"success temp",
			emailSecond,
			usernameSecond,
			pwdSecond,
			hex.EncodeToString(idSecond.Public.Key[:]),
			true,
			cms.ContractorTypeTemp,
			nil,
		},
	}

	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {

			inviteUserReq := cms.InviteNewUser{
				Email:     v.email,
				Temporary: v.temp,
			}
			reply, err := p.processInviteNewUser(inviteUserReq)
			if err != nil {
				t.Errorf("error inviting user %v %v", v.username, err)
				return
			}
			verificationToken := reply.VerificationToken

			registerReq := cms.RegisterUser{
				Email:             v.email,
				Username:          v.username,
				Password:          v.pwd,
				VerificationToken: verificationToken,
				PublicKey:         v.pubkey,
			}
			_, err = p.processRegisterUser(registerReq)
			if err != nil {
				t.Errorf("error registering user %v %v", v.username, err)
				return
			}

			u, err := p.db.UserGetByPubKey(v.pubkey)
			if err != nil {
				t.Errorf("error getting user by pubkey %v %v", v.username, err)
				return
			}

			cmsUser, err := p.getCMSUserByID(u.ID.String())
			if err != nil {
				t.Errorf("error getting cms user by id %v %v", u.ID.String(), err)
				return
			}

			if cmsUser.ContractorType != v.expectedContractorType {
				t.Errorf("unexpected contractor type got %v, want %v",
					cmsUser.ContractorType, v.expectedContractorType)
			}
			got := errToStr(err)
			want := errToStr(v.wantError)
			if got != want {
				t.Errorf("got error %v, want %v", got, want)
			}
		})
	}
}
