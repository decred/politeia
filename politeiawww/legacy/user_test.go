// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package legacy

import (
	"encoding/hex"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/legacy/user"
	"github.com/decred/politeia/util"
	"github.com/go-test/deep"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
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
		{
			"valid pubkey",
			valid,
			nil,
		},
		{
			"invalid hexadecimal",
			invalidHex,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidPublicKey,
			},
		},
		{
			"invalid size",
			invalidSize,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidPublicKey,
			},
		},
		{
			"empty pubkey",
			empty,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidPublicKey,
			},
		},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			err := validatePubKey(v.pubkey)
			got := errToStr(err)
			want := errToStr(v.want)
			if got != want {
				t.Errorf("got error %v, want %v", got, want)
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
		{
			"contains uppercase",
			"Politeiauser",
			www.UserError{
				ErrorCode: www.ErrorStatusMalformedUsername,
			},
		},
		{
			"leading whitespace",
			" politeiauser",
			www.UserError{
				ErrorCode: www.ErrorStatusMalformedUsername,
			},
		},
		{
			"trailing whitespace",
			"politeiauser ",
			www.UserError{
				ErrorCode: www.ErrorStatusMalformedUsername,
			},
		},
		{
			"empty",
			"",
			www.UserError{
				ErrorCode: www.ErrorStatusMalformedUsername,
			},
		},
		{
			"under min length",
			underMin,
			www.UserError{
				ErrorCode: www.ErrorStatusMalformedUsername,
			},
		},
		{
			"over max length",
			overMax,
			www.UserError{
				ErrorCode: www.ErrorStatusMalformedUsername,
			},
		},
		{
			"unsupported character",
			"politeiauser?",
			www.UserError{
				ErrorCode: www.ErrorStatusMalformedUsername,
			},
		},
		{
			"contains whitespace",
			"politeia user",
			www.UserError{
				ErrorCode: www.ErrorStatusMalformedUsername,
			},
		},
		{
			"valid username",
			"politeiauser",
			nil,
		},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			err := validateUsername(v.username)
			got := errToStr(err)
			want := errToStr(v.want)
			if got != want {
				t.Errorf("got error %v, want %v", got, want)
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
		{
			"user not found",
			www.VerifyNewUser{
				Email:             "invalidemail",
				VerificationToken: token,
				Signature:         sig,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusVerificationTokenInvalid,
			},
		},
		{
			"invalid verification token",
			www.VerifyNewUser{
				Email:             usr.Email,
				VerificationToken: "zzz",
				Signature:         sig,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusVerificationTokenInvalid,
			},
		},
		{
			"wrong verification token",
			www.VerifyNewUser{
				Email:             usr.Email,
				VerificationToken: wrongToken,
				Signature:         sig,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusVerificationTokenInvalid,
			},
		},
		{
			"expired verification token",
			www.VerifyNewUser{
				Email:             expiredUsr.Email,
				VerificationToken: expiredToken,
				Signature:         expiredSig,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusVerificationTokenExpired,
			},
		},
		{
			"invalid signature",
			www.VerifyNewUser{
				Email:             usr.Email,
				VerificationToken: token,
				Signature:         "abc",
			},
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidSignature,
			},
		},

		// I didn't test the ErrorStatusNoPublicKey error path because
		// I don't think it is possible for that error path to be hit.
		// A user always has an active identity.

		{
			"wrong signature",
			www.VerifyNewUser{
				Email:             usr.Email,
				VerificationToken: token,
				Signature:         wrongSig,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidSignature,
			},
		},
		{
			"success",
			www.VerifyNewUser{
				Email:             usr.Email,
				VerificationToken: token,
				Signature:         sig,
			},
			nil,
		},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			_, err := p.processVerifyNewUser(v.input)
			got := errToStr(err)
			want := errToStr(v.want)
			if got != want {
				t.Errorf("got error %v, want %v", got, want)
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

func TestProcessUpdateUserKey(t *testing.T) {

	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	// Create an user with an unexpired verification token
	usrUnexpired, id := newUser(t, p, true, false)
	token, expiry, err := newVerificationTokenAndExpiry()
	if err != nil {
		t.Fatal(err)
	}
	usrUnexpired.UpdateKeyVerificationToken = token
	usrUnexpired.UpdateKeyVerificationExpiry = expiry
	duppk := id.Public.String()

	err = p.db.UserUpdate(*usrUnexpired)
	if err != nil {
		t.Fatal(err)
	}

	// Create a user with an expired verification token.
	usr, _ := newUser(t, p, true, false)
	tokenb, _, err := newVerificationTokenAndExpiry()
	if err != nil {
		t.Fatal(err)
	}
	usr.UpdateKeyVerificationToken = tokenb
	usr.UpdateKeyVerificationExpiry = time.Now().Unix() - 1
	err = p.db.UserUpdate(*usr)
	if err != nil {
		t.Fatal(err)
	}

	newid, _ := identity.New()
	newpk := newid.Public.String()

	var tests = []struct {
		name string
		usr  *user.User
		uuk  www.UpdateUserKey
		want error
	}{
		{
			"user with duplicate pubkey",
			usrUnexpired,
			www.UpdateUserKey{
				PublicKey: duppk,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusDuplicatePublicKey,
			},
		},
		{
			"user with expired verification token",
			usrUnexpired,
			www.UpdateUserKey{
				PublicKey: newpk,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusVerificationTokenUnexpired,
			},
		},
		{
			"success with new pubkey",
			usr,
			www.UpdateUserKey{
				PublicKey: newpk,
			},
			nil,
		},
	}
	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			_, err := p.processUpdateUserKey(v.usr, v.uuk)
			got := errToStr(err)
			want := errToStr(v.want)
			if got != want {
				t.Errorf("got error %v, want %v",
					got, want)
			}
		})
	}
}

func TestProcessVerifyUpdateUserKey(t *testing.T) {
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	// Create an user with an unexpired verification token
	usr, id := newUser(t, p, true, false)
	token, expiry, err := newVerificationTokenAndExpiry()
	if err != nil {
		t.Fatal(err)
	}
	usr.UpdateKeyVerificationToken = token
	usr.UpdateKeyVerificationExpiry = expiry

	pubkey := hex.EncodeToString(id.Public.Key[:])
	newid, _ := user.NewIdentity(pubkey)
	usr.Identities = []user.Identity{
		*newid,
	}

	usrToken := hex.EncodeToString(token)

	s := id.SignMessage([]byte(usrToken))
	sig := hex.EncodeToString(s[:])

	err = p.db.UserUpdate(*usr)
	if err != nil {
		t.Fatal(err)
	}

	// Create a user with an expired verification token.
	usrExpired, idex := newUser(t, p, true, false)
	tokenb, _, err := newVerificationTokenAndExpiry()
	usrExpiredToken := hex.EncodeToString(tokenb)
	sxp := idex.SignMessage([]byte(usrExpiredToken))
	sigxp := hex.EncodeToString(sxp[:])

	if err != nil {
		t.Fatal(err)
	}
	usrExpired.UpdateKeyVerificationToken = tokenb
	usrExpired.UpdateKeyVerificationExpiry = time.Now().Unix() - 1
	err = p.db.UserUpdate(*usrExpired)
	if err != nil {
		t.Fatal(err)
	}

	var tests = []struct {
		name string
		usr  *user.User
		vu   www.VerifyUpdateUserKey
		want error
	}{
		{
			"invalid verification token",
			usr,
			www.VerifyUpdateUserKey{
				VerificationToken: "",
				Signature:         sig,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusVerificationTokenInvalid,
			},
		},
		{
			"unmatching verification tokens",
			usr,
			www.VerifyUpdateUserKey{
				VerificationToken: usrExpiredToken,
				Signature:         sigxp,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusVerificationTokenInvalid,
			},
		},
		{
			"expired verification token",
			usrExpired,
			www.VerifyUpdateUserKey{
				VerificationToken: usrExpiredToken,
				Signature:         sigxp,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusVerificationTokenExpired,
			},
		},
		{
			"invalid signature",
			usr,
			www.VerifyUpdateUserKey{
				VerificationToken: usrToken,
				Signature:         "",
			},
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidSignature,
			},
		},
		{
			"signature not matching pubkey",
			usr,
			www.VerifyUpdateUserKey{
				VerificationToken: usrToken,
				Signature:         sigxp,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidSignature,
			},
		},
		{
			"verify update user key",
			usr,
			www.VerifyUpdateUserKey{
				VerificationToken: usrToken,
				Signature:         sig,
			},
			nil,
		},
	}

	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			_, err := p.processVerifyUpdateUserKey(v.usr, v.vu)
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
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	// newUser() sets the password to be the username, which is
	// why we keep setting the passwords to be the the usernames.

	// Create an unverified user
	usrUnverified, _ := newUser(t, p, false, false)
	usrUnverifiedPassword := usrUnverified.Username

	// Create a user and lock their account from failed login
	// attempts.
	usrLocked, _ := newUser(t, p, true, false)
	usrLocked.FailedLoginAttempts = LoginAttemptsToLockUser + 1
	err := p.db.UserUpdate(*usrLocked)
	if err != nil {
		t.Fatal(err)
	}
	usrLockedPassword := usrLocked.Username

	// Create a deactivated user
	usrDeactivated, _ := newUser(t, p, true, false)
	usrDeactivated.Deactivated = true
	err = p.db.UserUpdate(*usrDeactivated)
	if err != nil {
		t.Fatal(err)
	}
	usrDeactivatedPassword := usrDeactivated.Username

	// Create a verified user and the expected login reply
	// for the success case.
	usr, id := newUser(t, p, true, false)
	usrPassword := usr.Username
	successReply := www.LoginReply{
		IsAdmin:            false,
		UserID:             usr.ID.String(),
		Email:              usr.Email,
		Username:           usr.Username,
		PublicKey:          id.Public.String(),
		PaywallAddress:     usr.NewUserPaywallAddress,
		PaywallAmount:      usr.NewUserPaywallAmount,
		PaywallTxNotBefore: usr.NewUserPaywallTxNotBefore,
		PaywallTxID:        "",
		ProposalCredits:    0,
		LastLoginTime:      0,
	}

	// Setup tests
	var tests = []struct {
		name      string
		login     www.Login
		wantReply *www.LoginReply
		wantError error
	}{
		{
			"wrong email",
			www.Login{
				Email:    "",
				Password: usrPassword,
			},
			nil,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidLogin,
			},
		},
		{
			"wrong password",
			www.Login{
				Email:    usr.Email,
				Password: "",
			},
			nil,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidLogin,
			},
		},
		{
			"user not verified",
			www.Login{
				Email:    usrUnverified.Email,
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
				Email:    usrDeactivated.Email,
				Password: usrDeactivatedPassword,
			},
			nil,
			www.UserError{
				ErrorCode: www.ErrorStatusUserDeactivated,
			},
		},
		{
			"user account locked",
			www.Login{
				Email:    usrLocked.Email,
				Password: usrLockedPassword,
			},
			nil,
			www.UserError{
				ErrorCode: www.ErrorStatusUserLocked,
			},
		},
		{
			"success",
			www.Login{
				Email:    usr.Email,
				Password: usrPassword,
			},
			&successReply,
			nil,
		},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			lr := p.login(v.login)
			gotErr := errToStr(lr.err)
			wantErr := errToStr(v.wantError)
			if gotErr != wantErr {
				t.Errorf("got error %v, want %v",
					gotErr, wantErr)
			}

			// If there were errors then we're done
			if err != nil {
				return
			}

			// Verify reply
			diff := deep.Equal(lr.reply, v.wantReply)
			if diff != nil {
				t.Errorf("got/want diff:\n%v",
					spew.Sdump(diff))
			}
		})
	}

	// Create TOTP Verified user
	usrTOTPVerified, idTOTP := newUser(t, p, true, false)

	opts := p.totpGenerateOpts(defaultPoliteiaIssuer, usrTOTPVerified.Username)
	key, err := totp.Generate(opts)
	if err != nil {
		t.Errorf("unable to generate secret key %v", err)
	}

	usrTOTPVerified.TOTPType = int(www.TOTPTypeBasic)
	usrTOTPVerified.TOTPSecret = key.Secret()
	usrTOTPVerified.TOTPLastUpdated = append(usrTOTPVerified.TOTPLastUpdated,
		time.Now().Unix())
	usrTOTPVerified.TOTPVerified = true
	err = p.db.UserUpdate(*usrTOTPVerified)
	if err != nil {
		t.Errorf("unable to update totp verified user %v", err)
	}

	usrTOTPVerifiedPassword := usrTOTPVerified.Username

	// Successful TOTP user reply
	successTOTPReply := www.LoginReply{
		IsAdmin:            false,
		UserID:             usrTOTPVerified.ID.String(),
		Email:              usrTOTPVerified.Email,
		Username:           usrTOTPVerified.Username,
		PublicKey:          idTOTP.Public.String(),
		PaywallAddress:     usrTOTPVerified.NewUserPaywallAddress,
		PaywallAmount:      usrTOTPVerified.NewUserPaywallAmount,
		PaywallTxNotBefore: usrTOTPVerified.NewUserPaywallTxNotBefore,
		PaywallTxID:        "",
		ProposalCredits:    0,
		LastLoginTime:      0,
		TOTPVerified:       true,
	}
	requestTime := time.Now()
	code, err := p.totpGenerateCode(key.Secret(), requestTime)
	if err != nil {
		t.Errorf("unable to generate code %v", err)
	}

	// Setup tests
	var testsTOTPVerified = []struct {
		name      string
		login     www.Login
		wantReply *www.LoginReply
		wantError error
	}{
		{
			"totp verified no code",
			www.Login{
				Email:    usrTOTPVerified.Email,
				Password: usrTOTPVerifiedPassword,
				Code:     "",
			},
			nil,
			www.UserError{
				ErrorCode: www.ErrorStatusRequiresTOTPCode,
			},
		},
		{
			"totp verified wrong code",
			www.Login{
				Email:    usrTOTPVerified.Email,
				Password: usrTOTPVerifiedPassword,
				Code:     "12345",
			},
			nil,
			www.UserError{
				ErrorCode: www.ErrorStatusTOTPFailedValidation,
			},
		},
		{
			"success totp verified",
			www.Login{
				Email:    usrTOTPVerified.Email,
				Password: usrTOTPVerifiedPassword,
				Code:     code,
			},
			&successTOTPReply,
			nil,
		},
	}

	// Run verified TOTP tests separate since they are time dependant.
	for _, v := range testsTOTPVerified {
		t.Run(v.name, func(t *testing.T) {
			lr := p.login(v.login)
			gotErr := errToStr(lr.err)
			wantErr := errToStr(v.wantError)
			if gotErr != wantErr {
				t.Logf("failed %v %v", requestTime, code)
				t.Errorf("got error %v, want %v",
					gotErr, wantErr)
			}

			// If there were errors then we're done
			if err != nil {
				return
			}

			// Verify reply
			diff := deep.Equal(lr.reply, v.wantReply)
			if diff != nil {
				t.Errorf("got/want diff:\n%v",
					spew.Sdump(diff))
			}
		})
	}

	// Create TOTP Verified Timed out user
	usrTOTPVerifiedTimeout, idTOTPTimeout := newUser(t, p, true, false)

	opts = p.totpGenerateOpts(defaultPoliteiaIssuer,
		usrTOTPVerifiedTimeout.Username)
	key, err = totp.Generate(opts)
	if err != nil {
		t.Errorf("unable to generate secret key %v", err)
	}

	// Add a delay based on the set totp test period.  This will allow for
	// testing weather or not only 2 failed totp attempts in a short period
	// of time (as opposed to the default 60s).
	futureCodeDelay := totpTestPeriod * time.Second
	futureCode, err := p.totpGenerateCode(key.Secret(),
		time.Now().Add(futureCodeDelay))
	if err != nil {
		t.Errorf("unable to generate future code %v", err)
	}

	usrTOTPVerifiedTimeout.TOTPType = int(www.TOTPTypeBasic)
	usrTOTPVerifiedTimeout.TOTPSecret = key.Secret()
	usrTOTPVerifiedTimeout.TOTPLastUpdated =
		append(usrTOTPVerified.TOTPLastUpdated, time.Now().Unix())
	usrTOTPVerifiedTimeout.TOTPVerified = true
	err = p.db.UserUpdate(*usrTOTPVerifiedTimeout)
	if err != nil {
		t.Errorf("unable to update totp verified user %v", err)
	}

	usrTOTPVerifiedTimeoutPassword := usrTOTPVerifiedTimeout.Username

	// Successful TOTP user reply
	successTOTPTimeoutReply := www.LoginReply{
		IsAdmin:            false,
		UserID:             usrTOTPVerifiedTimeout.ID.String(),
		Email:              usrTOTPVerifiedTimeout.Email,
		Username:           usrTOTPVerifiedTimeout.Username,
		PublicKey:          idTOTPTimeout.Public.String(),
		PaywallAddress:     usrTOTPVerifiedTimeout.NewUserPaywallAddress,
		PaywallAmount:      usrTOTPVerifiedTimeout.NewUserPaywallAmount,
		PaywallTxNotBefore: usrTOTPVerifiedTimeout.NewUserPaywallTxNotBefore,
		PaywallTxID:        "",
		ProposalCredits:    0,
		LastLoginTime:      0,
		TOTPVerified:       true,
	}

	// Setup tests
	var testsTOTPVerifiedTimeout = []struct {
		name      string
		login     www.Login
		wantReply *www.LoginReply
		wantError error
	}{
		{
			"totp verified timeout first incorrect",
			www.Login{
				Email:    usrTOTPVerifiedTimeout.Email,
				Password: usrTOTPVerifiedTimeoutPassword,
				Code:     "12345",
			},
			nil,
			www.UserError{
				ErrorCode: www.ErrorStatusTOTPFailedValidation,
			},
		},
		{
			"totp verified timeout second incorrect",
			www.Login{
				Email:    usrTOTPVerifiedTimeout.Email,
				Password: usrTOTPVerifiedTimeoutPassword,
				Code:     "12345",
			},
			nil,
			www.UserError{
				ErrorCode: www.ErrorStatusTOTPFailedValidation,
			},
		},
		{
			"totp verified timeout third incorrect timeout",
			www.Login{
				Email:    usrTOTPVerifiedTimeout.Email,
				Password: usrTOTPVerifiedTimeoutPassword,
				Code:     "12345",
			},
			nil,
			www.UserError{
				ErrorCode: www.ErrorStatusTOTPWaitForNewCode,
			},
		},
		{
			"error after timeout",
			www.Login{
				Email:    usrTOTPVerifiedTimeout.Email,
				Password: usrTOTPVerifiedTimeoutPassword,
				Code:     "12345",
			},
			nil,
			www.UserError{
				ErrorCode: www.ErrorStatusTOTPFailedValidation,
			},
		},
		{
			"success after timeout",
			www.Login{
				Email:    usrTOTPVerifiedTimeout.Email,
				Password: usrTOTPVerifiedTimeoutPassword,
				Code:     futureCode,
			},
			&successTOTPTimeoutReply,
			nil,
		},
	}
	// Run verified TOTP timeout tests separate since they are time dependant.
	for _, v := range testsTOTPVerifiedTimeout {
		t.Run(v.name, func(t *testing.T) {
			if v.name == "error after timeout" {
				time.Sleep(futureCodeDelay)
			}
			lr := p.login(v.login)
			gotErr := errToStr(lr.err)
			wantErr := errToStr(v.wantError)
			if gotErr != wantErr {
				t.Errorf("got error %v, want %v",
					gotErr, wantErr)
			}

			// If there were errors then we're done
			if err != nil {
				return
			}

			// Verify reply
			diff := deep.Equal(lr.reply, v.wantReply)
			if diff != nil {
				t.Errorf("got/want diff:\n%v",
					spew.Sdump(diff))
			}
		})
	}
}

func TestProcessLogin(t *testing.T) {
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	// loginMinWaitTime is a global variable that is used to
	// prevent timing attacks on login requests. Its normally set
	// to 500 milliseconds. We temporarily reduce it to 50ms for
	// these tests so that they don't take as long to run.
	m := loginMinWaitTime
	loginMinWaitTime = 50 * time.Millisecond
	defer func() {
		loginMinWaitTime = m
	}()

	// Test the incorrect email error path because it's
	// the quickest failure path for the login route.
	start := time.Now()
	_, err := p.processLogin(www.Login{})
	end := time.Now()
	elapsed := end.Sub(start)

	got := errToStr(err)
	want := www.ErrorStatus[www.ErrorStatusInvalidLogin]
	if got != want {
		t.Errorf("got error %v, want %v",
			got, want)
	}
	if elapsed < loginMinWaitTime {
		t.Errorf("execution time got %v, want >%v",
			elapsed, loginMinWaitTime)
	}

	// Test a successful login. newUser() sets the password
	// to be the username, which is why we pass the username
	// into the password field.
	u, _ := newUser(t, p, true, false)
	start = time.Now()
	lr, err := p.processLogin(www.Login{
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
	case elapsed < loginMinWaitTime:
		t.Errorf("execution time got %v, want >%v",
			elapsed, loginMinWaitTime)
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
		{
			"wrong current password",
			www.ChangePassword{
				CurrentPassword: "wrong!",
				NewPassword:     newPass,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidPassword,
			},
		},
		{
			"invalid new password",
			www.ChangePassword{
				CurrentPassword: currPass,
				NewPassword:     "",
			},
			www.UserError{
				ErrorCode: www.ErrorStatusMalformedPassword,
			},
		},
		{
			"success",
			www.ChangePassword{
				CurrentPassword: currPass,
				NewPassword:     newPass,
			},
			nil,
		},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			_, err := p.processChangePassword(u.Email, v.cp)
			got := errToStr(err)
			want := errToStr(v.want)
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

	// Test resetPasswordMinWaitTime
	t.Run("minimum wait time", func(t *testing.T) {
		usr, _ := newUser(t, p, true, false)
		rp := www.ResetPassword{
			Username: usr.Username,
			Email:    usr.Email,
		}
		start := time.Now()
		rpr, err := p.processResetPassword(rp)

		// Ensure the wait time is being adhered to.
		if time.Since(start) < resetPasswordMinWaitTime {
			t.Fatalf("min wait time violated")
		}

		// Check reply
		got := errToStr(err)
		if err != nil {
			t.Fatalf("got error %v, want nil", got)
		}
		if rpr.VerificationToken == "" {
			t.Errorf("verification token not sent")
		}
	})

	// Remove the min wait time requirement so that the
	// remaining tests aren't super slow.
	wt := resetPasswordMinWaitTime
	resetPasswordMinWaitTime = 0 * time.Millisecond
	defer func() {
		resetPasswordMinWaitTime = wt
	}()

	// Setup test data

	// Create a user with no verification token yet.
	usrNoToken, _ := newUser(t, p, true, false)

	// Create a user with an unexpired verification token.
	usrUnexpired, _ := newUser(t, p, true, false)
	tokenb, expiry, err := newVerificationTokenAndExpiry()
	if err != nil {
		t.Fatal(err)
	}
	usrUnexpired.ResetPasswordVerificationToken = tokenb
	usrUnexpired.ResetPasswordVerificationExpiry = expiry
	err = p.db.UserUpdate(*usrUnexpired)
	if err != nil {
		t.Fatal(err)
	}

	// Create a user with an expired verification token.
	usrExpired, _ := newUser(t, p, true, false)
	tokenb, _, err = newVerificationTokenAndExpiry()
	if err != nil {
		t.Fatal(err)
	}
	usrExpired.ResetPasswordVerificationToken = tokenb
	usrExpired.ResetPasswordVerificationExpiry = time.Now().Unix() - 1
	err = p.db.UserUpdate(*usrExpired)
	if err != nil {
		t.Fatal(err)
	}

	// Setup tests
	var tests = []struct {
		name      string
		rp        www.ResetPassword
		wantErr   error
		wantToken bool // Should the verification token have been sent
	}{
		{
			"invalid username",
			www.ResetPassword{
				Username: "wrongusername",
				Email:    usrNoToken.Email,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusUserNotFound,
			},
			false,
		},
		{
			"wrong email",
			www.ResetPassword{
				Username: usrNoToken.Username,
				Email:    "wrongemail",
			},
			nil,
			false,
		},
		// User has already requested a reset password
		// verification token and it has not expired.
		{
			"unexpired verification token",
			www.ResetPassword{
				Username: usrUnexpired.Username,
				Email:    usrUnexpired.Email,
			},
			nil,
			false,
		},
		// User has already requested a reset password
		// verification token but the token is expired.
		{
			"expired verification token",
			www.ResetPassword{
				Username: usrExpired.Username,
				Email:    usrExpired.Email,
			},
			nil,
			true,
		},
		// User has not yet requested a reset password
		// verification token.
		{
			"no token",
			www.ResetPassword{
				Username: usrNoToken.Username,
				Email:    usrNoToken.Email,
			},
			nil,
			true,
		},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			rpr, err := p.processResetPassword(v.rp)
			got := errToStr(err)
			want := errToStr(v.wantErr)
			if got != want {
				t.Errorf("got error %v, want %v", got, want)
			}

			// Check if the verification token was successfully
			// sent. The email server is disabled for testing so
			// if the token is in the reply then it is considered
			// to have been successfully sent.
			if v.wantToken && rpr.VerificationToken == "" {
				t.Errorf("verification token not sent")
			}
		})
	}
}

func TestProcessVerifyResetPassword(t *testing.T) {
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	// Create a user with an unexpired verification token
	usrUnexpired, _ := newUser(t, p, true, false)
	token, expiry, err := newVerificationTokenAndExpiry()
	if err != nil {
		t.Fatal(err)
	}
	usrUnexpired.ResetPasswordVerificationToken = token
	usrUnexpired.ResetPasswordVerificationExpiry = expiry
	err = p.db.UserUpdate(*usrUnexpired)
	if err != nil {
		t.Fatal(err)
	}
	usrUnexpiredToken := hex.EncodeToString(token)

	// Create a user with an exipred verification token
	usrExpired, _ := newUser(t, p, true, false)
	token, _, err = newVerificationTokenAndExpiry()
	if err != nil {
		t.Fatal(err)
	}
	usrExpired.ResetPasswordVerificationToken = token
	usrExpired.ResetPasswordVerificationExpiry = time.Now().Unix() - 1
	err = p.db.UserUpdate(*usrExpired)
	if err != nil {
		t.Fatal(err)
	}
	usrExpiredToken := hex.EncodeToString(token)

	// Create a locked user with an unexpired verification token.
	usrLocked, _ := newUser(t, p, true, false)
	token, expiry, err = newVerificationTokenAndExpiry()
	if err != nil {
		t.Fatal(err)
	}
	usrLocked.ResetPasswordVerificationToken = token
	usrLocked.ResetPasswordVerificationExpiry = expiry
	usrLocked.FailedLoginAttempts = LoginAttemptsToLockUser
	err = p.db.UserUpdate(*usrLocked)
	if err != nil {
		t.Fatal(err)
	}
	usrLockedToken := hex.EncodeToString(token)

	// Create a new password
	h, err := p.hashPassword("newpassword")
	if err != nil {
		t.Fatal(err)
	}
	newPass := hex.EncodeToString(h)

	// Setup tests
	var tests = []struct {
		name    string
		vrp     www.VerifyResetPassword
		wantErr error
	}{
		{
			"user not found",
			www.VerifyResetPassword{
				Username:          "badusername",
				VerificationToken: usrUnexpiredToken,
				NewPassword:       newPass,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusUserNotFound,
			},
		},
		{
			"no verification token",
			www.VerifyResetPassword{
				Username:          usrUnexpired.Username,
				VerificationToken: "",
				NewPassword:       newPass,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusVerificationTokenInvalid,
			},
		},
		{
			"invalid verification token",
			www.VerifyResetPassword{
				Username:          usrUnexpired.Username,
				VerificationToken: "invalidtoken",
				NewPassword:       newPass,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusVerificationTokenInvalid,
			},
		},
		{
			"wrong verification token",
			www.VerifyResetPassword{
				Username:          usrUnexpired.Username,
				VerificationToken: usrExpiredToken,
				NewPassword:       newPass,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusVerificationTokenInvalid,
			},
		},
		{
			"expired verification token",
			www.VerifyResetPassword{
				Username:          usrExpired.Username,
				VerificationToken: usrExpiredToken,
				NewPassword:       newPass,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusVerificationTokenExpired,
			},
		},
		{
			"invalid password",
			www.VerifyResetPassword{
				Username:          usrUnexpired.Username,
				VerificationToken: usrUnexpiredToken,
				NewPassword:       "",
			},
			www.UserError{
				ErrorCode: www.ErrorStatusMalformedPassword,
			},
		},
		{
			"success",
			www.VerifyResetPassword{
				Username:          usrUnexpired.Username,
				VerificationToken: usrUnexpiredToken,
				NewPassword:       newPass,
			},
			nil,
		},
		{
			"success with locked account",
			www.VerifyResetPassword{
				Username:          usrLocked.Username,
				VerificationToken: usrLockedToken,
				NewPassword:       newPass,
			},
			nil,
		},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			_, err := p.processVerifyResetPassword(v.vrp)
			got := errToStr(err)
			want := errToStr(v.wantErr)
			if got != want {
				t.Errorf("got error %v, want %v", got, want)
				return
			}

			// If there were no errors, ensure that the user password
			// was updated correctly, the user account was unlocked,
			// and the verification token fields were cleared out.
			if err == nil {
				u, err := p.db.UserGetByUsername(v.vrp.Username)
				if err != nil {
					t.Fatal(err)
				}
				err = bcrypt.CompareHashAndPassword(u.HashedPassword,
					[]byte(v.vrp.NewPassword))
				if err != nil {
					if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
						t.Errorf("user password not updated")
					}
					t.Fatal(err)
				}
				switch {
				case userIsLocked(u.FailedLoginAttempts):
					t.Errorf("user account is still locked")
				case u.ResetPasswordVerificationToken != nil:
					t.Errorf("verification token not nil")
				case u.ResetPasswordVerificationExpiry != 0:
					t.Errorf("verification expiry not 0")
				}
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
		{
			"wrong password",
			u.Email,
			www.ChangeUsername{
				Password: "wrong",
			},
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidPassword,
			},
		},
		{
			"invalid username",
			u.Email,
			www.ChangeUsername{
				Password:    password,
				NewUsername: "?",
			},
			www.UserError{
				ErrorCode: www.ErrorStatusMalformedUsername,
			},
		},
		{
			"duplicate username",
			u.Email,
			www.ChangeUsername{
				Password:    password,
				NewUsername: u.Username,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusDuplicateUsername,
			},
		},
		{
			"success",
			u.Email,
			www.ChangeUsername{
				Password:    password,
				NewUsername: "politeiauser",
			},
			nil,
		},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			_, err := p.processChangeUsername(v.email, v.cu)
			got := errToStr(err)
			want := errToStr(v.want)
			if got != want {
				t.Errorf("got error %v, want %v", got, want)
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
		{
			"public user details",
			ud, false, false,
			publicUser,
			publicUserMsg,
		},
		{
			"admin requesting user details",
			ud, false, true,
			fullUser,
			fullUserMsg,
		},

		{
			"user requesting their own details",
			ud, true, false,
			fullUser,
			fullUserMsg,
		},
		{
			"admin requesting their own details",
			ud, true, true,
			fullUser,
			fullUserMsg,
		},
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
		{
			"single notification setting",
			0x1,
			[]www.EmailNotificationT{
				www.NotificationEmailMyProposalStatusChange,
			},
		},
		{
			"multiple notification settings",
			0x7,
			[]www.EmailNotificationT{
				www.NotificationEmailMyProposalStatusChange,
				www.NotificationEmailMyProposalVoteStarted,
				www.NotificationEmailRegularProposalVetted,
			},
		},
		{
			"no notification settings",
			0x0,
			[]www.EmailNotificationT{},
		},
		{
			"invalid notification setting",
			0x100000,
			[]www.EmailNotificationT{},
		},
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
				t.Errorf("notification bits got %#x, want %#x", bitsGot, bitsWant)
			}
		})
	}
}

func TestProcessManageUser(t *testing.T) {
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	// Create a new user. This is the user
	// that we will be managing.
	usr, _ := newUser(t, p, true, false)
	uid := usr.ID.String()

	// Create a new admin. This user will be
	// used to manage the user
	admin, _ := newUser(t, p, true, false)

	var tests = []struct {
		name  string
		mu    www.ManageUser
		admin *user.User
		want  error
	}{
		{
			"invalid manage action",
			www.ManageUser{
				UserID: uid,
				Action: www.UserManageInvalid,
				Reason: "reason",
			},
			admin,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidUserManageAction,
			},
		},
		{
			"invalid reason",
			www.ManageUser{
				UserID: uid,
				Action: www.UserManageExpireNewUserVerification,
				Reason: "",
			},
			admin,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			},
		},
		{
			"unsupported edit action",
			www.ManageUser{
				UserID: uid,
				Action: 9,
				Reason: "reason",
			},
			admin,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidUserManageAction,
			},
		},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			_, err := p.processManageUser(&v.mu, v.admin)
			got := errToStr(err)
			want := errToStr(v.want)
			if got != want {
				t.Errorf("got error %v, want %v",
					got, want)
			}
		})
	}
}

func TestProcessUsers(t *testing.T) {
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	// Create a new user.
	usr, id := newUser(t, p, true, false)
	// Create an admin user.
	adm, _ := newUser(t, p, true, true)

	usrpk := id.Public.String()

	// empty user list
	empty := make([]www.AbridgedUser, 0, www.UserListPageSize)
	usrlistpub := append(empty, www.AbridgedUser{
		ID:       usr.ID.String(),
		Email:    "",
		Username: usr.Username,
	})

	var allusers = []www.AbridgedUser{
		{
			ID:       adm.ID.String(),
			Email:    adm.Email,
			Username: adm.Username,
		},
		{
			ID:       usr.ID.String(),
			Email:    usr.Email,
			Username: usr.Username,
		},
	}
	// sorts all users buy username
	sort.Slice(allusers, func(i, j int) bool {
		return allusers[i].Username < allusers[j].Username
	})

	var tests = []struct {
		name      string
		u         www.Users
		isAdmin   bool
		wantReply www.UsersReply
	}{
		{
			"pubkey not found",
			www.Users{
				PublicKey: "",
			},
			false,
			www.UsersReply{
				Users: empty,
			},
		},
		{
			"email not found",
			www.Users{
				Email: "notfound",
			},
			false,
			www.UsersReply{
				Users: empty,
			},
		},
		{
			"username not found",
			www.Users{
				Username: "notfound",
			},
			false,
			www.UsersReply{
				Users: empty,
			},
		},
		{
			"regular users can find users by pubkey",
			www.Users{
				PublicKey: usrpk,
			},
			false,
			www.UsersReply{
				Users:        usrlistpub,
				TotalMatches: 1,
			},
		},
		{
			"regular users can find users by username",
			www.Users{
				Username: usr.Username,
			},
			false,
			www.UsersReply{
				Users:        usrlistpub,
				TotalMatches: 1,
			},
		},
		{
			"regular users can't find users by email",
			www.Users{
				Email: usr.Email,
			},
			false,
			www.UsersReply{
				Users: empty,
			},
		},
		{
			"admin can find user by pubkey",
			www.Users{
				PublicKey: usrpk,
			},
			true,
			www.UsersReply{
				Users: []www.AbridgedUser{
					{
						Username: usr.Username,
						Email:    usr.Email,
						ID:       usr.ID.String(),
					},
				},
				TotalMatches: 1,
				TotalUsers:   2,
			},
		},
		{
			"admin can find user by email",
			www.Users{
				Email: usr.Email,
			},
			true,
			www.UsersReply{
				Users: []www.AbridgedUser{
					{
						Username: usr.Username,
						Email:    usr.Email,
						ID:       usr.ID.String(),
					},
				},
				TotalMatches: 1,
				TotalUsers:   2,
			},
		},
		{
			"admin can find user by username",
			www.Users{
				Username: usr.Username,
			},
			true,
			www.UsersReply{
				Users: []www.AbridgedUser{
					{
						Username: usr.Username,
						Email:    usr.Email,
						ID:       usr.ID.String(),
					},
				},
				TotalMatches: 1,
				TotalUsers:   2,
			},
		},
		{
			"admin fetches all users when email is empty",
			www.Users{
				Email: "",
			},
			true,
			www.UsersReply{
				Users:        allusers,
				TotalMatches: 2,
				TotalUsers:   2,
			},
		},
		{
			"admin fetches all users when username is empty",
			www.Users{
				Username: "",
			},
			true,
			www.UsersReply{
				Users:        allusers,
				TotalMatches: 2,
				TotalUsers:   2,
			},
		},
		{
			"admin fetches all users when pubkey is empty",
			www.Users{
				PublicKey: "",
			},
			true,
			www.UsersReply{
				Users:        allusers,
				TotalMatches: 2,
				TotalUsers:   2,
			},
		},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			pur, err := p.processUsers(&v.u, v.isAdmin)
			if err != nil {
				return
			}
			// Verify reply
			diff := deep.Equal(*pur, v.wantReply)
			if diff != nil {
				t.Errorf("got/want diff:\n%v",
					spew.Sdump(diff))
			}
		})
	}
}

func TestProcessSetTOTP(t *testing.T) {
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	basicUser, _ := newUser(t, p, true, false)

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
	}

	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			reply, err := p.processSetTOTP(v.params, v.user)

			got := errToStr(err)
			want := errToStr(v.wantError)
			if got != want {
				t.Errorf("got %v, want %v", got, want)
				return
			}

			if err != nil {
				return
			}
			userInfo, err := p.userByIDStr(v.user.ID.String())
			if err != nil {
				t.Errorf("unable to get update user %v", err)
				return
			}
			if userInfo.TOTPSecret != reply.Key {
				t.Error("secret returned does not match saved key")
			}
		})
	}

	// Set up separate tests for testing already set totp key
	alreadySetUser, _ := newUser(t, p, true, false)

	opts := p.totpGenerateOpts(defaultPoliteiaIssuer, alreadySetUser.Username)
	key, err := totp.Generate(opts)
	if err != nil {
		t.Errorf("unable to generate secret key %v", err)
	}

	alreadySetUser.TOTPType = int(www.TOTPTypeBasic)
	alreadySetUser.TOTPSecret = key.Secret()
	alreadySetUser.TOTPVerified = true
	alreadySetUser.TOTPLastUpdated = append(alreadySetUser.TOTPLastUpdated,
		time.Now().Unix())

	err = p.db.UserUpdate(*alreadySetUser)
	if err != nil {
		t.Errorf("unable to update user secret key %v", err)
	}
	requestTime := time.Now()
	code, err := p.totpGenerateCode(key.Secret(), requestTime)
	if err != nil {
		t.Errorf("unable to generate code %v", err)
	}

	// We run separate tests because these are time dependant because of codes
	// generated.
	var alreadySetTests = []struct {
		name      string
		params    www.SetTOTP
		wantError error
		user      *user.User
	}{
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
	for _, v := range alreadySetTests {
		t.Run(v.name, func(t *testing.T) {
			reply, err := p.processSetTOTP(v.params, v.user)

			// Check to see that expected errors match
			got := errToStr(err)
			want := errToStr(v.wantError)
			if got != want {
				t.Errorf("got %v, want %v", got, want)
				return
			}

			if err != nil {
				return
			}
			userInfo, err := p.userByIDStr(v.user.ID.String())
			if err != nil {
				t.Errorf("unable to get update user %v", err)
				return
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

	opts := p.totpGenerateOpts(defaultPoliteiaIssuer, usr.Username)
	key, err := totp.Generate(opts)
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

	code, err := p.totpGenerateCode(key.Secret(), time.Now())
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
