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
	v1 "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/util"
	"github.com/go-test/deep"
)

func TestValidatePubkey(t *testing.T) {
	p := newTestPoliteiawww(t)
	defer cleanupTestPoliteiawww(t, p)

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
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidPublicKey,
			}},

		{"invalid size", invalidSize,
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidPublicKey,
			}},

		{"empty pubkey", empty,
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidPublicKey,
			}},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			_, err := validatePubkey(v.pubkey)
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
	p := newTestPoliteiawww(t)
	defer cleanupTestPoliteiawww(t, p)

	// Username under the min length requirement
	var underMin string
	for i := 0; i < v1.PolicyMinUsernameLength-1; i++ {
		underMin += "0"
	}

	// Username over the max length requirement
	var overMax string
	for i := 0; i < v1.PolicyMaxUsernameLength+1; i++ {
		overMax += "0"
	}

	// Setup tests
	var tests = []struct {
		name     string
		username string
		want     error
	}{
		{"contains uppercase", "Politeiauser",
			v1.UserError{
				ErrorCode: v1.ErrorStatusMalformedUsername,
			}},

		{"leading whitespace", " politeiauser",
			v1.UserError{
				ErrorCode: v1.ErrorStatusMalformedUsername,
			}},

		{"trailing whitespace", "politeiauser ",
			v1.UserError{
				ErrorCode: v1.ErrorStatusMalformedUsername,
			}},

		{"empty", "",
			v1.UserError{
				ErrorCode: v1.ErrorStatusMalformedUsername,
			}},

		{"under min length", underMin,
			v1.UserError{
				ErrorCode: v1.ErrorStatusMalformedUsername,
			}},

		{"over max length", overMax,
			v1.UserError{
				ErrorCode: v1.ErrorStatusMalformedUsername,
			}},

		{"unsupported character", "politeiauser?",
			v1.UserError{
				ErrorCode: v1.ErrorStatusMalformedUsername,
			}},

		{"contains whitespace", "politeia user",
			v1.UserError{
				ErrorCode: v1.ErrorStatusMalformedUsername,
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
	p := newTestPoliteiawww(t)
	defer cleanupTestPoliteiawww(t, p)

	// Password under the min length requirement
	var minPass string
	for i := 0; i < v1.PolicyMinPasswordLength-1; i++ {
		minPass += "0"
	}

	// Setup tests
	var tests = []struct {
		name     string
		password string
		want     error
	}{
		{"under min length", minPass,
			v1.UserError{
				ErrorCode: v1.ErrorStatusMalformedPassword,
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
	p := newTestPoliteiawww(t)
	defer cleanupTestPoliteiawww(t, p)

	// Create a verified user
	usrVerified, _ := newUser(t, p, true, false)

	// Create an unverified user with an unexpired
	// verification token.
	usrUnexpired, _ := newUser(t, p, false, false)

	// Create an unverified user with an expired verification
	// token. We do this by creating an unverified user then
	// manually updating the expiration time in the database. A
	// user with an expired verification token is allowed to send
	// up a new pubkey if they want to update their identity. We
	// create a new pubkey to test this.
	usrExpired, _ := newUser(t, p, false, false)
	usrExpired.NewUserVerificationExpiry = time.Now().Unix() - 1
	err := p.db.UserUpdate(*usrExpired)
	if err != nil {
		t.Fatalf("%v", err)
	}

	id, err := identity.New()
	if err != nil {
		t.Fatalf("%v", err)
	}
	usrExpiredPublicKey := id.Public.String()

	// Create valid user credentials to use in the tests.
	id, err = identity.New()
	if err != nil {
		t.Fatalf("%v", err)
	}

	r, err := util.Random(int(v1.PolicyMinPasswordLength))
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
		newUser v1.NewUser
		want    error
	}{
		{"verified user",
			v1.NewUser{
				Email: usrVerified.Email,
			}, nil},

		{"unverified user unexpired token",
			v1.NewUser{
				Email: usrUnexpired.Email,
			},
			nil},

		{"unverified user expired token",
			v1.NewUser{
				Email:     usrExpired.Email,
				Password:  "password",
				PublicKey: usrExpiredPublicKey,
				Username:  usrExpired.Username,
			}, nil},

		{"invalid pubkey",
			v1.NewUser{
				Email:     validEmail,
				Password:  validPassword,
				PublicKey: "",
				Username:  validUsername,
			},
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidPublicKey,
			}},

		{"invalid username",
			v1.NewUser{
				Email:     validEmail,
				Password:  validPassword,
				PublicKey: validPublicKey,
				Username:  "",
			},
			v1.UserError{
				ErrorCode: v1.ErrorStatusMalformedUsername,
			}},

		{"invalid password",
			v1.NewUser{
				Email:     validEmail,
				Password:  "",
				PublicKey: validPublicKey,
				Username:  validUsername,
			},
			v1.UserError{
				ErrorCode: v1.ErrorStatusMalformedPassword,
			}},

		// usrExpired gets successfully created during the test
		// "unverified user expired token" so usrExpiredPublicKey
		// should now be a duplicate.
		{"duplicate pubkey",
			v1.NewUser{
				Email:     validEmail,
				Password:  validPassword,
				PublicKey: usrExpiredPublicKey,
				Username:  validUsername,
			},
			v1.UserError{
				ErrorCode: v1.ErrorStatusDuplicatePublicKey,
			}},

		{"invalid email",
			v1.NewUser{
				Email:     "",
				Password:  validPassword,
				PublicKey: validPublicKey,
				Username:  validUsername,
			},
			v1.UserError{
				ErrorCode: v1.ErrorStatusMalformedEmail,
			}},

		{"valid new user",
			v1.NewUser{
				Email:     validEmail,
				Password:  validPassword,
				PublicKey: validPublicKey,
				Username:  validUsername,
			}, nil},
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
	p := newTestPoliteiawww(t)
	defer cleanupTestPoliteiawww(t, p)

	// Create a user with a valid, unexpired verification
	// token.
	usr, id := newUser(t, p, false, false)
	token := hex.EncodeToString(usr.NewUserVerificationToken)
	s := id.SignMessage([]byte(token))
	sig := hex.EncodeToString(s[:])

	s = id.SignMessage([]byte("intentionally wrong"))
	wrongSig := hex.EncodeToString(s[:])

	// Create a token that does not correspond to a user
	b, _, err := generateVerificationTokenAndExpiry()
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
		input v1.VerifyNewUser
		want  error
	}{
		// An invalid token error is thrown when the user lookup
		// fails so that info about which email addresses exist
		// cannot be ascertained.
		{"user not found",
			v1.VerifyNewUser{
				Email:             "invalidemail",
				VerificationToken: token,
				Signature:         sig,
			},
			v1.UserError{
				ErrorCode: v1.ErrorStatusVerificationTokenInvalid,
			}},

		{"invalid verification token",
			v1.VerifyNewUser{
				Email:             usr.Email,
				VerificationToken: "zzz",
				Signature:         sig,
			},
			v1.UserError{
				ErrorCode: v1.ErrorStatusVerificationTokenInvalid,
			}},

		{"wrong verification token",
			v1.VerifyNewUser{
				Email:             usr.Email,
				VerificationToken: wrongToken,
				Signature:         sig,
			},
			v1.UserError{
				ErrorCode: v1.ErrorStatusVerificationTokenInvalid,
			}},

		{"expired verification token",
			v1.VerifyNewUser{
				Email:             expiredUsr.Email,
				VerificationToken: expiredToken,
				Signature:         expiredSig,
			},
			v1.UserError{
				ErrorCode: v1.ErrorStatusVerificationTokenExpired,
			}},

		{"invalid signature",
			v1.VerifyNewUser{
				Email:             usr.Email,
				VerificationToken: token,
				Signature:         "abc",
			},
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidSignature,
			}},

		// I didn't test the ErrorStatusNoPublicKey error path because
		// I don't think it is possible for that error path to be hit.
		// A user always has an active identity.

		{"wrong signature",
			v1.VerifyNewUser{
				Email:             usr.Email,
				VerificationToken: token,
				Signature:         wrongSig,
			},
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidSignature,
			}},

		{"success",
			v1.VerifyNewUser{
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
	p := newTestPoliteiawww(t)
	defer cleanupTestPoliteiawww(t, p)

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
		rv   v1.ResendVerification
		want error
	}{
		{"user not found",
			v1.ResendVerification{
				Email: "someuser@example.com",
			},
			v1.UserError{
				ErrorCode: v1.ErrorStatusUserNotFound,
			}},

		{"user already verified",
			v1.ResendVerification{
				Email: usrVerified.Email,
			},
			v1.UserError{
				ErrorCode: v1.ErrorStatusEmailAlreadyVerified,
			}},

		{"invalid pubkey",
			v1.ResendVerification{
				Email:     usr1.Email,
				PublicKey: "",
			},
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidPublicKey,
			}},

		{"duplicate pubkey",
			v1.ResendVerification{
				Email:     usr1.Email,
				PublicKey: usrVerifiedPubkey,
			},
			v1.UserError{
				ErrorCode: v1.ErrorStatusDuplicatePublicKey,
			}},

		// If the user has an unexpired token, they are allowed
		// to resend the verification email one time. The second
		// attempt should fail.
		{"success",
			v1.ResendVerification{
				Email:     usr1.Email,
				PublicKey: usr1Pubkey,
			}, nil},

		{"unexpired token",
			v1.ResendVerification{
				Email: usr1.Email,
			},
			v1.UserError{
				ErrorCode: v1.ErrorStatusVerificationTokenUnexpired,
			}},

		// The user does not have to pass in the same pubkey that
		// is currently saved in the database. If they do use a
		// different pubkey, their active identity in the database
		// is updated to reflect the new pubkey.
		{"success with new pubkey",
			v1.ResendVerification{
				Email:     usr2.Email,
				PublicKey: usr2Pubkey,
			}, nil},
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

func TestLogin(t *testing.T) {
	p := newTestPoliteiawww(t)
	defer cleanupTestPoliteiawww(t, p)

	// newUser() sets the password to be the username, which is
	// why we keep setting the passwords to be the the usernames.

	// Create a verified user to test against
	usr, id := newUser(t, p, true, false)
	usrPassword := usr.Username

	// Create the expected login reply
	reply := v1.LoginReply{
		IsAdmin:            false,
		UserID:             usr.ID.String(),
		Email:              usr.Email,
		PublicKey:          id.Public.String(),
		PaywallAddress:     usr.NewUserPaywallAddress,
		PaywallAmount:      usr.NewUserPaywallAmount,
		PaywallTxNotBefore: usr.NewUserPaywallTxNotBefore,
		PaywallTxID:        "",
		ProposalCredits:    0,
		LastLoginTime:      0,
		SessionMaxAge:      sessionMaxAge,
	}

	// Create an unverified user
	usrUnverified, id := newUser(t, p, false, false)
	usrUnverifiedPassword := usrUnverified.Username

	// Create a user and lock their account from failed login
	// attempts.
	usrLocked, _ := newUser(t, p, true, false)
	usrLocked.FailedLoginAttempts = LoginAttemptsToLockUser + 1
	err := p.db.UserUpdate(*usrLocked)
	if err != nil {
		t.Fatalf("%v", err)
	}
	usrLockedPassword := usrLocked.Username

	// Create a deactivated user
	usrDeactivated, _ := newUser(t, p, true, false)
	usrDeactivated.Deactivated = true
	err = p.db.UserUpdate(*usrDeactivated)
	if err != nil {
		t.Fatalf("%v", err)
	}
	usrDeactivatedPassword := usrDeactivated.Username

	var tests = []struct {
		name      string
		login     v1.Login
		wantReply *v1.LoginReply
		wantError error
	}{
		{"wrong email",
			v1.Login{
				Email:    "",
				Password: usrPassword,
			}, nil,
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidEmailOrPassword,
			}},

		{"wrong password",
			v1.Login{
				Email:    usr.Email,
				Password: "",
			}, nil,
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidEmailOrPassword,
			}},

		{"user not verified",
			v1.Login{
				Email:    usrUnverified.Email,
				Password: usrUnverifiedPassword,
			}, nil,
			v1.UserError{
				ErrorCode: v1.ErrorStatusEmailNotVerified,
			}},

		{"user deactivated",
			v1.Login{
				Email:    usrDeactivated.Email,
				Password: usrDeactivatedPassword,
			}, nil,
			v1.UserError{
				ErrorCode: v1.ErrorStatusUserDeactivated,
			}},

		{"user locked",
			v1.Login{
				Email:    usrLocked.Email,
				Password: usrLockedPassword,
			}, nil,
			v1.UserError{
				ErrorCode: v1.ErrorStatusUserLocked,
			}},

		{"success",
			v1.Login{
				Email:    usr.Email,
				Password: usrPassword,
			}, &reply, nil},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			lr := p.login(&v.login)
			got := errToStr(lr.err)
			want := errToStr(v.wantError)
			if got != want {
				t.Errorf("got error %v, want %v",
					got, want)
			}
		})
	}

}

func TestProcessLogin(t *testing.T) {
	p := newTestPoliteiawww(t)
	defer cleanupTestPoliteiawww(t, p)

	// MinimumLoginWaitTime is a global variable that is used to
	// prevent timing attacks on login requests. Its normally set
	// to 500 milliseconds. We reduce it to 100ms for these tests
	// because 100ms still serves the intended purpose in a test
	// enviroment.
	MinimumLoginWaitTime = 100 * time.Millisecond

	// Test the incorrect email error path because it's
	// the quickest failure path for the login route.
	start := time.Now()
	_, err := p.processLogin(v1.Login{})
	end := time.Now()
	elapsed := end.Sub(start)

	got := errToStr(err)
	want := v1.ErrorStatus[v1.ErrorStatusInvalidEmailOrPassword]
	if got != want {
		t.Errorf("got error %v, want %v", got, want)
	}
	if elapsed < MinimumLoginWaitTime {
		t.Errorf("execution time got %v, want >%v",
			elapsed, MinimumLoginWaitTime)
	}

	// Test a successful login. newUser() sets the
	// password to be the username, which is why we
	// pass the username into the password field.
	u, _ := newUser(t, p, true, false)
	start = time.Now()
	lr, err := p.processLogin(v1.Login{
		Email:    u.Email,
		Password: u.Username,
	})
	end = time.Now()
	elapsed = end.Sub(start)
	got = errToStr(err)

	switch {
	case got != "nil":
		t.Errorf("got error %v, want nil", got)

	case lr.UserID != u.ID.String():
		t.Errorf("login reply userID got %v, want %v",
			lr.UserID, u.ID.String())

	case elapsed < MinimumLoginWaitTime:
		t.Errorf("execution time got %v, want >%v",
			elapsed, MinimumLoginWaitTime)
	}
}

func TestProcessChangePassword(t *testing.T) {
	p := newTestPoliteiawww(t)
	defer cleanupTestPoliteiawww(t, p)

	// Create a new user. newUser() sets the password
	// as the username, which is why currPass is set
	// to be the username.
	u, _ := newUser(t, p, true, false)
	currPass := u.Username

	r, err := util.Random(int(v1.PolicyMinPasswordLength))
	if err != nil {
		t.Fatalf("%v", err)
	}
	newPass := hex.EncodeToString(r)

	// Setup tests
	var tests = []struct {
		name string
		cp   v1.ChangePassword
		want error
	}{
		{"wrong current password",
			v1.ChangePassword{
				CurrentPassword: "wrong!",
				NewPassword:     newPass,
			},
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidEmailOrPassword,
			}},

		{"invalid new password",
			v1.ChangePassword{
				CurrentPassword: currPass,
				NewPassword:     "",
			},
			v1.UserError{
				ErrorCode: v1.ErrorStatusMalformedPassword,
			}},

		{"success",
			v1.ChangePassword{
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
	p := newTestPoliteiawww(t)
	defer cleanupTestPoliteiawww(t, p)

	// Create a normal user that we can test against
	usr, _ := newUser(t, p, true, false)
	r, err := util.Random(int(v1.PolicyMinPasswordLength))
	if err != nil {
		t.Fatalf("%v", err)
	}
	newPassword := hex.EncodeToString(r)

	// Create a user with a verification token already set
	usrUnexpired, _ := newUser(t, p, true, false)
	token, expiry, err := generateVerificationTokenAndExpiry()
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
	token, expiry, err = generateVerificationTokenAndExpiry()
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
	token, expiry, err = generateVerificationTokenAndExpiry()
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
		rp   v1.ResetPassword
		want error
	}{
		// processRestPassword is unique in that it expects the user
		// to call it twice. The first time without a verification
		// token included in the request and the second time with a
		// verification token included in the request.

		// No request verification token

		{"user not found",
			v1.ResetPassword{
				Email: "abc",
			},
			v1.UserError{
				ErrorCode: v1.ErrorStatusUserNotFound,
			}},

		{"unexpired token",
			v1.ResetPassword{
				Email: usrUnexpired.Email,
			}, nil},

		{"expired token",
			v1.ResetPassword{
				Email: usrExpired.Email,
			}, nil},

		{"sucess",
			v1.ResetPassword{
				Email: usr.Email,
			}, nil},

		// With a request verification token

		{"invalid token",
			v1.ResetPassword{
				Email:             usr.Email,
				VerificationToken: "xxx",
			},
			v1.UserError{
				ErrorCode: v1.ErrorStatusVerificationTokenInvalid,
			}},

		{"wrong token",
			v1.ResetPassword{
				Email:             usr.Email,
				VerificationToken: usrUnexpiredToken,
			},
			v1.UserError{
				ErrorCode: v1.ErrorStatusVerificationTokenInvalid,
			}},

		{"expired token",
			v1.ResetPassword{
				Email:             usrExpired2.Email,
				VerificationToken: usrExpired2Token,
			},
			v1.UserError{
				ErrorCode: v1.ErrorStatusVerificationTokenExpired,
			}},

		{"invalid password",
			v1.ResetPassword{
				Email:             usrUnexpired.Email,
				VerificationToken: usrUnexpiredToken,
				NewPassword:       "",
			},
			v1.UserError{
				ErrorCode: v1.ErrorStatusMalformedPassword,
			}},

		{"success",
			v1.ResetPassword{
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
	p := newTestPoliteiawww(t)
	defer cleanupTestPoliteiawww(t, p)

	// Create a new user. newUser() sets
	// the password to be the username.
	u, _ := newUser(t, p, true, false)
	password := u.Username

	// Setup tests
	var tests = []struct {
		name  string
		email string
		cu    v1.ChangeUsername
		want  error
	}{
		{"wrong password", u.Email,
			v1.ChangeUsername{
				Password: "wrong",
			},
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidEmailOrPassword,
			}},

		{"invalid username", u.Email,
			v1.ChangeUsername{
				Password:    password,
				NewUsername: "?",
			},
			v1.UserError{
				ErrorCode: v1.ErrorStatusMalformedUsername,
			}},

		{"duplicate username", u.Email,
			v1.ChangeUsername{
				Password:    password,
				NewUsername: u.Username,
			},
			v1.UserError{
				ErrorCode: v1.ErrorStatusDuplicateUsername,
			}},

		{"success", u.Email,
			v1.ChangeUsername{
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
	p := newTestPoliteiawww(t)
	defer cleanupTestPoliteiawww(t, p)

	// Create a new user. This is the UUID that
	// we'll use to test the UserDetails route.
	u, _ := newUser(t, p, true, false)
	ud := v1.UserDetails{}

	// Test a valid length UUID that does not belong to a user.
	// We can assume that any invalid UUIDs were caught by the
	// user details request handler.
	t.Run("valid UUID with no user", func(t *testing.T) {
		ud.UserID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
		_, err := p.processUserDetails(&ud, false, false)
		got := errToStr(err)
		want := v1.ErrorStatus[v1.ErrorStatusUserNotFound]
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
		name          string         // Test name
		ud            v1.UserDetails // User details request
		isCurrentUser bool           // Is a user requesting their own details
		isAdmin       bool           // Is an admin requesting the user details
		wantUsr       v1.User        // Wanted user response
		wantMsg       string         // Description of the wanted user response
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
	p := newTestPoliteiawww(t)
	defer cleanupTestPoliteiawww(t, p)

	// Create a new user. This is the user
	// that we will be editing.
	user, _ := newUser(t, p, true, false)

	// Setup test cases
	tests := []struct {
		name         string
		notification uint64
		want         []v1.EmailNotificationT
	}{
		{"single notification setting", 0x1,
			[]v1.EmailNotificationT{
				v1.NotificationEmailMyProposalStatusChange,
			}},

		{"multiple notification settings", 0x7,
			[]v1.EmailNotificationT{
				v1.NotificationEmailMyProposalStatusChange,
				v1.NotificationEmailMyProposalVoteStarted,
				v1.NotificationEmailRegularProposalVetted,
			}},

		{"no notification settings", 0x0,
			[]v1.EmailNotificationT{}},

		{"invalid notification setting", 0x100000,
			[]v1.EmailNotificationT{}},
	}

	// Run test cases
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := p.processEditUser(&v1.EditUser{
				EmailNotifications: &test.notification,
			}, user)
			if err != nil {
				t.Errorf("got error %v, want nil", err)
			}

			// Ensure database was updated with
			// correct notification settings.
			u, err := p.db.UserGet(user.Email)
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
