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
