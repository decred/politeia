// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/util"
	"github.com/go-test/deep"
)

func TestValidatePubkey(t *testing.T) {
	id, err := identity.New()
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Valid public key
	valid := id.Public.String()

	// Invalid hex string. The last character is an 'x'.
	invalidHex := "62920bbb25dd552c7367677be0abe19f4c11394c82ce4096eabf83469439901x"

	// The private key is 64 bytes so we can use it to test
	// the invalid size error path. The expected size of the
	// public key is 32 bytes.
	invalidSize := hex.EncodeToString(id.PrivateKey[:])

	// Valid size public key that is all zeros
	var zeros [identity.PublicKeySize]byte
	empty := hex.EncodeToString(zeros[:])

	// Setup tests
	var tests = []struct {
		name   string
		pubkey string
		want   error
	}{
		{"valid pubkey", valid, nil},

		{"invalid hexadecimal", invalidHex,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidPublicKey,
			}},

		{"invalid size", invalidSize,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidPublicKey,
			}},

		{"empty pubkey", empty,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidPublicKey,
			}},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			err := validatePubKey(v.pubkey)
			got := errToStr(err)
			want := errToStr(v.want)
			if got != want {
				t.Errorf("got error %v, want %v",
					got, want)
			}
		})
	}
}

func TestValidateUsername(t *testing.T) {
	// Username under the min length requirement
	var underMin string
	for i := 0; i < www.PolicyMinUsernameLength-1; i++ {
		underMin += "0"
	}

	// Username over the max length requirement
	var overMax string
	for i := 0; i < www.PolicyMaxUsernameLength+1; i++ {
		overMax += "0"
	}

	// Setup tests
	var tests = []struct {
		name     string
		username string
		want     error
	}{
		{"contains uppercase", "Politeiauser",
			www.UserError{
				ErrorCode: www.ErrorStatusMalformedUsername,
			}},

		{"leading whitespace", " politeiauser",
			www.UserError{
				ErrorCode: www.ErrorStatusMalformedUsername,
			}},

		{"trailing whitespace", "politeiauser ",
			www.UserError{
				ErrorCode: www.ErrorStatusMalformedUsername,
			}},

		{"empty", "",
			www.UserError{
				ErrorCode: www.ErrorStatusMalformedUsername,
			}},

		{"under min length", underMin,
			www.UserError{
				ErrorCode: www.ErrorStatusMalformedUsername,
			}},

		{"over max length", overMax,
			www.UserError{
				ErrorCode: www.ErrorStatusMalformedUsername,
			}},

		{"unsupported character", "politeiauser?",
			www.UserError{
				ErrorCode: www.ErrorStatusMalformedUsername,
			}},

		{"contains whitespace", "politeia user",
			www.UserError{
				ErrorCode: www.ErrorStatusMalformedUsername,
			}},

		{"valid username", "politeiauser", nil},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			err := validateUsername(v.username)
			got := errToStr(err)
			want := errToStr(v.want)
			if got != want {
				t.Errorf("got error %v, want %v",
					got, want)
			}
		})
	}
}

func TestValidatePassword(t *testing.T) {
	// Password under the min length requirement
	var minPass string
	for i := 0; i < www.PolicyMinPasswordLength-1; i++ {
		minPass += "0"
	}

	// Setup tests
	var tests = []struct {
		name     string
		password string
		want     error
	}{
		{"under min length", minPass,
			www.UserError{
				ErrorCode: www.ErrorStatusMalformedPassword,
			}},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			err := validatePassword(v.password)
			got := errToStr(err)
			want := errToStr(v.want)
			if got != want {
				t.Errorf("got error %v, want %v",
					got, want)
			}
		})
	}
}

func TestProcessNewUser(t *testing.T) {
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	// Create a verified user
	usrVerified, _ := newUser(t, p, true, false)

	// Create an unverified user with an unexpired
	// verification token.
	usrUnexpired, id := newUser(t, p, false, false)
	usrUnexpiredPublicKey := id.Public.String()

	// Create two unverified users with expired verification tokens.
	// The verification tokens are expired manually. A user with an
	// expired verification token is allowed to use a new pubkey if
	// they want to update their identity.
	//
	// usrExpiredSame will use the same pubkey that is saved to the db.
	// usrExpiredDiff will use a different pubkey to test the identity
	// update path.
	usrExpiredSame, id := newUser(t, p, false, false)
	usrExpiredSame.NewUserVerificationExpiry = time.Now().Unix() - 1
	err := p.db.UserUpdate(*usrExpiredSame)
	if err != nil {
		t.Fatal(err)
	}
	usrExpiredSamePublicKey := id.Public.String()

	usrExpiredDiff, _ := newUser(t, p, false, false)
	usrExpiredDiff.NewUserVerificationExpiry = time.Now().Unix() - 1
	err = p.db.UserUpdate(*usrExpiredDiff)
	if err != nil {
		t.Fatal(err)
	}
	id, err = identity.New()
	if err != nil {
		t.Fatal(err)
	}
	usrExpiredDiffPublicKey := id.Public.String()

	// Create valid user credentials to use in the tests.
	id, err = identity.New()
	if err != nil {
		t.Fatalf("%v", err)
	}
	r, err := util.Random(int(www.PolicyMinPasswordLength))
	if err != nil {
		t.Fatalf("%v", err)
	}
	validEmail := hex.EncodeToString(r) + "@example.com"
	validUsername := hex.EncodeToString(r)
	validPassword := hex.EncodeToString(r)
	validPublicKey := id.Public.String()

	// Setup tests
	var tests = []struct {
		name    string
		newUser www.NewUser
		want    error
	}{
		{
			"invalid email",
			www.NewUser{
				Email:     "",
				Password:  validPassword,
				PublicKey: validPublicKey,
				Username:  validUsername,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusMalformedEmail,
			},
		},
		{
			"invalid pubkey",
			www.NewUser{
				Email:     validEmail,
				Password:  validPassword,
				PublicKey: "",
				Username:  validUsername,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidPublicKey,
			},
		},
		{
			"invalid username",
			www.NewUser{
				Email:     validEmail,
				Password:  validPassword,
				PublicKey: validPublicKey,
				Username:  "",
			},
			www.UserError{
				ErrorCode: www.ErrorStatusMalformedUsername,
			},
		},
		{
			"invalid password",
			www.NewUser{
				Email:     validEmail,
				Password:  "",
				PublicKey: validPublicKey,
				Username:  validUsername,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusMalformedPassword,
			},
		},
		{
			"user already verified",
			www.NewUser{
				Email:     usrVerified.Email,
				Password:  validPassword,
				PublicKey: usrVerified.PublicKey(),
				Username:  usrVerified.Username,
			},
			nil,
		},
		{
			"unverified user unexpired token",
			www.NewUser{
				Email:     usrUnexpired.Email,
				Password:  validPassword,
				PublicKey: usrUnexpiredPublicKey,
				Username:  usrUnexpired.Username,
			},
			nil,
		},
		{
			"unverified user expired token same pubkey",
			www.NewUser{
				Email:     usrExpiredSame.Email,
				Password:  validPassword,
				PublicKey: usrExpiredSamePublicKey,
				Username:  usrExpiredSame.Username,
			},
			nil,
		},
		{
			"unverified user expired token different pubkey",
			www.NewUser{
				Email:     usrExpiredDiff.Email,
				Password:  validPassword,
				PublicKey: usrExpiredDiffPublicKey,
				Username:  usrExpiredDiff.Username,
			},
			nil,
		},
		{
			"duplicate username",
			www.NewUser{
				Email:     validEmail,
				Password:  validPassword,
				PublicKey: validPublicKey,
				Username:  usrVerified.Username,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusDuplicateUsername,
			},
		},
		{
			"duplicate pubkey",
			www.NewUser{
				Email:     validEmail,
				Password:  validPassword,
				PublicKey: usrVerified.PublicKey(),
				Username:  validUsername,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusDuplicatePublicKey,
			},
		},
		{
			"valid new user",
			www.NewUser{
				Email:     validEmail,
				Password:  validPassword,
				PublicKey: validPublicKey,
				Username:  validUsername,
			},
			nil,
		},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			_, err := p.processNewUser(v.newUser)
			got := errToStr(err)
			want := errToStr(v.want)
			if got != want {
				t.Errorf("got error %v, want %v",
					got, want)
			}
		})
	}
}

func TestProcessVerifyNewUser(t *testing.T) {
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	// Create a user with a valid, unexpired verification
	// token.
	usr, id := newUser(t, p, false, false)
	token := hex.EncodeToString(usr.NewUserVerificationToken)
	s := id.SignMessage([]byte(token))
	sig := hex.EncodeToString(s[:])

	s = id.SignMessage([]byte("intentionally wrong"))
	wrongSig := hex.EncodeToString(s[:])

	// Create a token that does not correspond to a user
	b, _, err := newVerificationTokenAndExpiry()
	if err != nil {
		t.Fatalf("%v", err)
	}
	wrongToken := hex.EncodeToString(b)

	// Create a user with an expired verification token
	expiredUsr, id := newUser(t, p, true, false)
	expiredUsr.NewUserVerificationExpiry = time.Now().Unix() - 1
	err = p.db.UserUpdate(*expiredUsr)
	if err != nil {
		t.Fatalf("%v", err)
	}
	expiredToken := hex.EncodeToString(expiredUsr.NewUserVerificationToken)
	s = id.SignMessage([]byte(expiredToken))
	expiredSig := hex.EncodeToString(s[:])

	// Setup tests
	var tests = []struct {
		name  string
		input www.VerifyNewUser
		want  error
	}{
		// An invalid token error is thrown when the user lookup
		// fails so that info about which email addresses exist
		// cannot be ascertained.
		{"user not found",
			www.VerifyNewUser{
				Email:             "invalidemail",
				VerificationToken: token,
				Signature:         sig,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusVerificationTokenInvalid,
			}},

		{"invalid verification token",
			www.VerifyNewUser{
				Email:             usr.Email,
				VerificationToken: "zzz",
				Signature:         sig,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusVerificationTokenInvalid,
			}},

		{"wrong verification token",
			www.VerifyNewUser{
				Email:             usr.Email,
				VerificationToken: wrongToken,
				Signature:         sig,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusVerificationTokenInvalid,
			}},

		{"expired verification token",
			www.VerifyNewUser{
				Email:             expiredUsr.Email,
				VerificationToken: expiredToken,
				Signature:         expiredSig,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusVerificationTokenExpired,
			}},

		{"invalid signature",
			www.VerifyNewUser{
				Email:             usr.Email,
				VerificationToken: token,
				Signature:         "abc",
			},
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidSignature,
			}},

		// I didn't test the ErrorStatusNoPublicKey error path because
		// I don't think it is possible for that error path to be hit.
		// A user always has an active identity.

		{"wrong signature",
			www.VerifyNewUser{
				Email:             usr.Email,
				VerificationToken: token,
				Signature:         wrongSig,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidSignature,
			}},

		{"success",
			www.VerifyNewUser{
				Email:             usr.Email,
				VerificationToken: token,
				Signature:         sig,
			},
			nil},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			_, err := p.processVerifyNewUser(v.input)
			got := errToStr(err)
			want := errToStr(v.want)
			if got != want {
				t.Errorf("got error %v, want %v",
					got, want)
			}
		})
	}
}

func TestProcessResendVerification(t *testing.T) {
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	// Create a verified user
	usrVerified, id := newUser(t, p, true, false)
	usrVerifiedPubkey := id.Public.String()

	// Create two unverified users
	usr1, id := newUser(t, p, false, false)
	usr1Pubkey := id.Public.String()
	usr2, _ := newUser(t, p, false, false)

	// A user is allowed to pass in a different pubkey
	// than is currently saved in the database. We give
	// usr2 a new pubkey to test this.
	id, err := identity.New()
	if err != nil {
		t.Fatalf("%v", err)
	}
	usr2Pubkey := id.Public.String()

	// Setup tests
	var tests = []struct {
		name string
		rv   www.ResendVerification
		want error
	}{
		{
			"user not found",
			www.ResendVerification{
				Email:     "someuser@example.com",
				PublicKey: usrVerifiedPubkey,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusUserNotFound,
			},
		},
		{
			"user already verified",
			www.ResendVerification{
				Email:     usrVerified.Email,
				PublicKey: usrVerifiedPubkey,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusEmailAlreadyVerified,
			},
		},
		{
			"invalid pubkey",
			www.ResendVerification{
				Email:     usr1.Email,
				PublicKey: "",
			},
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidPublicKey,
			},
		},
		{
			"duplicate pubkey",
			www.ResendVerification{
				Email:     usr1.Email,
				PublicKey: usrVerifiedPubkey,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusDuplicatePublicKey,
			},
		},
		// If the user has an unexpired token, they are allowed
		// to resend the verification email one time. The second
		// attempt should fail.
		{
			"success",
			www.ResendVerification{
				Email:     usr1.Email,
				PublicKey: usr1Pubkey,
			},
			nil,
		},
		{
			"unexpired token",
			www.ResendVerification{
				Email:     usr1.Email,
				PublicKey: usr1Pubkey,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusVerificationTokenUnexpired,
			},
		},
		// The user does not have to pass in the same pubkey that
		// is currently saved in the database. If they do use a
		// different pubkey, their active identity in the database
		// is updated to reflect the new pubkey.
		{
			"success with new pubkey",
			www.ResendVerification{
				Email:     usr2.Email,
				PublicKey: usr2Pubkey,
			},
			nil,
		},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			_, err := p.processResendVerification(&v.rv)
			got := errToStr(err)
			want := errToStr(v.want)
			if got != want {
				t.Errorf("got error %v, want %v",
					got, want)
			}
		})
	}
}

func TestProcessLogin(t *testing.T) {
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	// newUser() sets the password to be the username. This is
	// why the test case passwords are set to be the usernames.

	// Test that the failed login attempts are being incremented
	// properly on the user object.
	t.Run("failed login attempts", func(t *testing.T) {
		usr, _ := newUser(t, p, true, false)
		l := www.Login{
			Username: usr.Username,
			Password: "wrongpassword",
		}
		_, err := p.processLogin(l)
		got := errToStr(err)
		want := www.ErrorStatus[www.ErrorStatusInvalidPassword]
		if got != want {
			t.Errorf("got error %v, want %v",
				got, want)
		}
		usr, err = p.db.UserGetById(usr.ID)
		if err != nil {
			t.Fatal(err)
		}
		if usr.FailedLoginAttempts != 1 {
			t.Errorf("failed login attempts got %v, want 1",
				usr.FailedLoginAttempts)
		}
	})

	// Create a verified user and the expected login reply.
	usr, id := newUser(t, p, true, false)
	usrPassword := usr.Username
	usrReply := www.LoginReply{
		IsAdmin:            false,
		UserID:             usr.ID.String(),
		Username:           usr.Username,
		Email:              usr.Email,
		PublicKey:          id.Public.String(),
		PaywallAddress:     usr.NewUserPaywallAddress,
		PaywallAmount:      usr.NewUserPaywallAmount,
		PaywallTxNotBefore: usr.NewUserPaywallTxNotBefore,
		PaywallTxID:        "",
		ProposalCredits:    0,
		LastLoginTime:      0,
	}

	// Create a user with a locked account
	usrLocked, _ := newUser(t, p, true, false)
	usrLocked.FailedLoginAttempts = LoginAttemptsToLockUser
	err := p.db.UserUpdate(*usrLocked)
	if err != nil {
		t.Fatal(err)
	}
	usrLockedPassword := usrLocked.Username

	// Create an unverified user
	usrUnverified, _ := newUser(t, p, false, false)
	usrUnverifiedPassword := usrUnverified.Username

	// Create a deactivated user
	usrDeactivated, _ := newUser(t, p, true, false)
	usrDeactivated.Deactivated = true
	err = p.db.UserUpdate(*usrDeactivated)
	if err != nil {
		t.Fatal(err)
	}
	usrDeactivatedPassword := usrDeactivated.Username

	// Setup tests
	var tests = []struct {
		name      string
		login     www.Login
		wantReply *www.LoginReply
		wantErr   error
	}{
		{
			"user not found",
			www.Login{
				Username: "",
				Password: usrPassword,
			},
			nil,
			www.UserError{
				ErrorCode: www.ErrorStatusUserNotFound,
			},
		},
		{
			"user locked",
			www.Login{
				Username: usrLocked.Username,
				Password: usrLockedPassword,
			},
			nil,
			www.UserError{
				ErrorCode: www.ErrorStatusUserLocked,
			},
		},
		{
			"wrong password",
			www.Login{
				Username: usr.Username,
				Password: "wrongpassword",
			},
			nil,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidPassword,
			},
		},
		{
			"user not verified",
			www.Login{
				Username: usrUnverified.Username,
				Password: usrUnverifiedPassword,
			},
			nil,
			www.UserError{
				ErrorCode: www.ErrorStatusEmailNotVerified,
			},
		},
		{
			"user deactivated",
			www.Login{
				Username: usrDeactivated.Username,
				Password: usrDeactivatedPassword,
			},
			nil,
			www.UserError{
				ErrorCode: www.ErrorStatusUserDeactivated,
			},
		},
		{
			"success",
			www.Login{
				Username: usr.Username,
				Password: usrPassword,
			},
			&usrReply,
			nil,
		},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			lr, err := p.processLogin(v.login)
			gotErr := errToStr(err)
			wantErr := errToStr(v.wantErr)
			if gotErr != wantErr {
				t.Errorf("got error %v, want %v",
					gotErr, wantErr)
			}

			// If there were errors then we're done.
			if err != nil {
				return
			}

			// Check the reply
			diff := deep.Equal(lr, v.wantReply)
			if diff != nil {
				t.Errorf("got/want diff:\n%v",
					spew.Sdump(diff))
			}
		})
	}
}

func TestProcessChangePassword(t *testing.T) {
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	// Create a new user. newUser() sets the password
	// as the username, which is why currPass is set
	// to be the username.
	u, _ := newUser(t, p, true, false)
	currPass := u.Username

	r, err := util.Random(int(www.PolicyMinPasswordLength))
	if err != nil {
		t.Fatalf("%v", err)
	}
	newPass := hex.EncodeToString(r)

	// Setup tests
	var tests = []struct {
		name string
		cp   www.ChangePassword
		want error
	}{
		{"wrong current password",
			www.ChangePassword{
				CurrentPassword: "wrong!",
				NewPassword:     newPass,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidPassword,
			}},

		{"invalid new password",
			www.ChangePassword{
				CurrentPassword: currPass,
				NewPassword:     "",
			},
			www.UserError{
				ErrorCode: www.ErrorStatusMalformedPassword,
			}},

		{"success",
			www.ChangePassword{
				CurrentPassword: currPass,
				NewPassword:     newPass,
			}, nil},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			_, err := p.processChangePassword(u.Email, v.cp)
			got := errToStr(err)
			want := errToStr(err)
			if got != want {
				t.Errorf("got error %v, want %v",
					got, want)
			}
		})
	}
}

func TestProcessResetPassword(t *testing.T) {
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	// Create a normal user that we can test against
	usr, _ := newUser(t, p, true, false)
	r, err := util.Random(int(www.PolicyMinPasswordLength))
	if err != nil {
		t.Fatalf("%v", err)
	}
	newPassword := hex.EncodeToString(r)

	// Create a user with a verification token already set
	usrUnexpired, _ := newUser(t, p, true, false)
	token, expiry, err := newVerificationTokenAndExpiry()
	if err != nil {
		t.Fatalf("%v", err)
	}
	usrUnexpired.ResetPasswordVerificationToken = token
	usrUnexpired.ResetPasswordVerificationExpiry = expiry
	err = p.db.UserUpdate(*usrUnexpired)
	if err != nil {
		t.Fatalf("%v", err)
	}
	usrUnexpiredToken := hex.EncodeToString(token)

	// Create two users with verification tokens already set and
	// that has already expired. The first expired user can't be
	// reused in the tests because the expired token gets reset.
	usrExpired, _ := newUser(t, p, true, false)
	token, _, err = newVerificationTokenAndExpiry()
	if err != nil {
		t.Fatalf("%v", err)
	}
	usrExpired.ResetPasswordVerificationToken = token
	usrExpired.ResetPasswordVerificationExpiry = time.Now().Unix() - 1
	err = p.db.UserUpdate(*usrExpired)
	if err != nil {
		t.Fatalf("%v", err)
	}

	usrExpired2, _ := newUser(t, p, true, false)
	token, _, err = newVerificationTokenAndExpiry()
	if err != nil {
		t.Fatalf("%v", err)
	}
	usrExpired2.ResetPasswordVerificationToken = token
	usrExpired2.ResetPasswordVerificationExpiry = time.Now().Unix() - 1
	err = p.db.UserUpdate(*usrExpired2)
	if err != nil {
		t.Fatalf("%v", err)
	}
	usrExpired2Token := hex.EncodeToString(token)

	// Setup tests
	var tests = []struct {
		name string
		rp   www.ResetPassword
		want error
	}{
		// processRestPassword is unique in that it expects the user
		// to call it twice. The first time without a verification
		// token included in the request and the second time with a
		// verification token included in the request.

		// No request verification token

		{"user not found",
			www.ResetPassword{
				Email: "abc",
			},
			www.UserError{
				ErrorCode: www.ErrorStatusUserNotFound,
			}},

		{"unexpired token",
			www.ResetPassword{
				Email: usrUnexpired.Email,
			}, nil},

		{"expired token",
			www.ResetPassword{
				Email: usrExpired.Email,
			}, nil},

		{"success",
			www.ResetPassword{
				Email: usr.Email,
			}, nil},

		// With a request verification token

		{"invalid token",
			www.ResetPassword{
				Email:             usr.Email,
				VerificationToken: "xxx",
			},
			www.UserError{
				ErrorCode: www.ErrorStatusVerificationTokenInvalid,
			}},

		{"wrong token",
			www.ResetPassword{
				Email:             usr.Email,
				VerificationToken: usrUnexpiredToken,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusVerificationTokenInvalid,
			}},

		{"expired token",
			www.ResetPassword{
				Email:             usrExpired2.Email,
				VerificationToken: usrExpired2Token,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusVerificationTokenExpired,
			}},

		{"invalid password",
			www.ResetPassword{
				Email:             usrUnexpired.Email,
				VerificationToken: usrUnexpiredToken,
				NewPassword:       "",
			},
			www.UserError{
				ErrorCode: www.ErrorStatusMalformedPassword,
			}},

		{"success",
			www.ResetPassword{
				Email:             usrUnexpired.Email,
				VerificationToken: usrUnexpiredToken,
				NewPassword:       newPassword,
			}, nil},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			_, err := p.processResetPassword(v.rp)
			got := errToStr(err)
			want := errToStr(v.want)
			if got != want {
				t.Errorf("got error %v, want %v",
					got, want)
			}
		})
	}
}

func TestProcessChangeUsername(t *testing.T) {
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	// Create a new user. newUser() sets
	// the password to be the username.
	u, _ := newUser(t, p, true, false)
	password := u.Username

	// Setup tests
	var tests = []struct {
		name  string
		email string
		cu    www.ChangeUsername
		want  error
	}{
		{"wrong password", u.Email,
			www.ChangeUsername{
				Password: "wrong",
			},
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidPassword,
			}},

		{"invalid username", u.Email,
			www.ChangeUsername{
				Password:    password,
				NewUsername: "?",
			},
			www.UserError{
				ErrorCode: www.ErrorStatusMalformedUsername,
			}},

		{"duplicate username", u.Email,
			www.ChangeUsername{
				Password:    password,
				NewUsername: u.Username,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusDuplicateUsername,
			}},

		{"success", u.Email,
			www.ChangeUsername{
				Password:    password,
				NewUsername: "politeiauser",
			}, nil},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			_, err := p.processChangeUsername(v.email, v.cu)
			got := errToStr(err)
			want := errToStr(v.want)
			if got != want {
				t.Errorf("got error %v, want %v",
					got, want)
			}
		})
	}
}

func TestProcessUserDetails(t *testing.T) {
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	// Create a new user. This is the UUID that
	// we'll use to test the UserDetails route.
	u, _ := newUser(t, p, true, false)
	ud := www.UserDetails{}

	// Test a valid length UUID that does not belong to a user.
	// We can assume that any invalid UUIDs were caught by the
	// user details request handler.
	t.Run("valid UUID with no user", func(t *testing.T) {
		ud.UserID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
		_, err := p.processUserDetails(&ud, false, false)
		got := errToStr(err)
		want := www.ErrorStatus[www.ErrorStatusUserNotFound]
		if got != want {
			t.Errorf("got error %v, want %v", got, want)
		}
	})

	// UserDetails will either return the full user details
	// or just the public user details depending on who is
	// requesting the data. The full user details includes
	// private data such as email address and payment info.
	fullUser := convertWWWUserFromDatabaseUser(u)
	fullUserMsg := "full user details"

	publicUser := filterUserPublicFields(fullUser)
	publicUserMsg := "public user details"

	// Use a valid UUID for the remaining tests
	ud.UserID = fullUser.ID

	// Setup tests
	var tests = []struct {
		name          string          // Test name
		ud            www.UserDetails // User details request
		isCurrentUser bool            // Is a user requesting their own details
		isAdmin       bool            // Is an admin requesting the user details
		wantUsr       www.User        // Wanted user response
		wantMsg       string          // Description of the wanted user response
	}{
		{"public user details", ud, false, false,
			publicUser, publicUserMsg},

		{"admin requesting user details", ud, false, true,
			fullUser, fullUserMsg},

		{"user requesting their own details", ud, true, false,
			fullUser, fullUserMsg},

		{"admin requesting their own details", ud, true, true,
			fullUser, fullUserMsg},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			udr, err := p.processUserDetails(&v.ud,
				v.isCurrentUser, v.isAdmin)
			if err != nil {
				t.Errorf("got error %v, want nil", err)
			}

			diff := deep.Equal(udr.User, v.wantUsr)
			if diff != nil {
				t.Errorf("want %v, got/want diff:\n%v",
					v.wantMsg, spew.Sdump(diff))
			}
		})
	}
}

func TestProcessEditUser(t *testing.T) {
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	// Create a new user. This is the user
	// that we will be editing.
	user, _ := newUser(t, p, true, false)

	// Setup test cases
	tests := []struct {
		name         string
		notification uint64
		want         []www.EmailNotificationT
	}{
		{"single notification setting", 0x1,
			[]www.EmailNotificationT{
				www.NotificationEmailMyProposalStatusChange,
			}},

		{"multiple notification settings", 0x7,
			[]www.EmailNotificationT{
				www.NotificationEmailMyProposalStatusChange,
				www.NotificationEmailMyProposalVoteStarted,
				www.NotificationEmailRegularProposalVetted,
			}},

		{"no notification settings", 0x0,
			[]www.EmailNotificationT{}},

		{"invalid notification setting", 0x100000,
			[]www.EmailNotificationT{}},
	}

	// Run test cases
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := p.processEditUser(&www.EditUser{
				EmailNotifications: &test.notification,
			}, user)
			if err != nil {
				t.Errorf("got error %v, want nil", err)
			}

			// Ensure database was updated with
			// correct notification settings.
			u, err := p.db.UserGetById(user.ID)
			if err != nil {
				t.Fatalf("%v", err)
			}

			var bitsWant uint64
			for _, notification := range test.want {
				bitsWant |= uint64(notification)
			}

			// Apply a mask to ignore invalid bits. The mask
			// represents all possible notification settings.
			var mask uint64 = 0x1FF
			bitsGot := u.EmailNotifications & mask
			if !(bitsWant|bitsGot == bitsWant) {
				t.Errorf("notification bits got %#x, want %#x",
					bitsGot, bitsWant)
			}
		})
	}
}
