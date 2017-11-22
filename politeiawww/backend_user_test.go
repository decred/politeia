package main

import (
	"encoding/hex"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"runtime/debug"
	"testing"
	"time"

	www "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/util"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func generateRandomString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func generateRandomEmail() string {
	return generateRandomString(8) + "@example.com"
}

func generateRandomPassword() string {
	return generateRandomString(www.PolicyPasswordMinChars)
}

func createBackend(t *testing.T) *backend {
	dir, err := ioutil.TempDir("", "politeiawww.test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	cfg := &config{
		DataDir: filepath.Join(dir, "data"),
	}

	b, err := NewBackend(cfg)
	if err != nil {
		t.Fatal(err)
	}

	b.test = true
	b.inventory = make([]www.ProposalRecord, 0)
	return b
}

func assertSuccess(t *testing.T, err error) {
	if err != nil {
		userErr, ok := err.(www.UserError)
		if ok {
			t.Fatalf("unexpected error code %v\n\n%s", userErr.ErrorCode, debug.Stack())
		} else {
			t.Fatalf("unexpected error: %v\n\n%s", err, debug.Stack())
		}
	}
}

func assertError(t *testing.T, err error, expectedStatus www.ErrorStatusT) {
	assertErrorWithContext(t, err, expectedStatus, []string{})
}

func assertErrorWithContext(t *testing.T, err error, expectedStatus www.ErrorStatusT, expectedContext []string) {
	if err != nil {
		userErr, ok := err.(www.UserError)
		if ok {
			if userErr.ErrorCode != expectedStatus {
				t.Fatalf("expected error code %v, was %v\n\n%s", expectedStatus, userErr.ErrorCode, debug.Stack())
			}
			if len(userErr.ErrorContext) == len(expectedContext) {
				for i, context := range userErr.ErrorContext {
					if context != expectedContext[i] {
						t.Fatalf("expected context %s, was %s\n\n%s", expectedContext, userErr.ErrorContext, debug.Stack())
					}
				}
			} else {
				t.Fatalf("expected context %v, was %v\n\n%s", expectedContext, userErr.ErrorContext, debug.Stack())
			}
		} else {
			t.Fatalf("unexpected error: %v\n\n%s", err, debug.Stack())
		}
	} else {
		t.Fatalf("expected error with code %v\n\n%s", expectedStatus, debug.Stack())
	}
}

func createAndVerifyUser(t *testing.T, b *backend) www.NewUser {
	nu := www.NewUser{
		Email:    generateRandomEmail(),
		Password: generateRandomPassword(),
	}

	nur, err := b.ProcessNewUser(nu)
	assertSuccess(t, err)

	bytes, err := hex.DecodeString(nur.VerificationToken)
	if err != nil {
		t.Fatal(err)
	}

	if len(bytes[:]) != www.VerificationTokenSize {
		t.Fatalf("token length was %v, expected %v", len(bytes[:]),
			www.VerificationTokenSize)
	}

	v := www.VerifyNewUser{
		Email:             nu.Email,
		VerificationToken: nur.VerificationToken,
	}
	err = b.ProcessVerifyNewUser(v)
	assertSuccess(t, err)

	return nu
}

// Tests creating a new user with an existing token which still needs to be verified.
func TestProcessNewUserWithUnverifiedToken(t *testing.T) {
	b := createBackend(t)

	u := www.NewUser{
		Email:    generateRandomEmail(),
		Password: generateRandomPassword(),
	}

	_, err := b.ProcessNewUser(u)
	assertSuccess(t, err)

	_, err = b.ProcessNewUser(u)
	assertSuccess(t, err)

	b.db.Close()
}

// Tests creating a new user which has an expired token.
func TestProcessNewUserWithExpiredToken(t *testing.T) {
	b := createBackend(t)

	b.verificationExpiryTime = time.Duration(100) * time.Nanosecond
	const sleepTime = time.Duration(2) * time.Second

	u := www.NewUser{
		Email:    generateRandomEmail(),
		Password: generateRandomPassword(),
	}

	reply1, err := b.ProcessNewUser(u)
	assertSuccess(t, err)

	// Sleep for a longer amount of time than it takes for the verification token to expire.
	time.Sleep(sleepTime)

	reply2, err := b.ProcessNewUser(u)
	assertSuccess(t, err)

	if reply2.VerificationToken == "" {
		t.Fatalf("ProcessNewUser did not return a verification token.")
	}
	if reply1.VerificationToken == reply2.VerificationToken {
		t.Fatalf("ProcessNewUser did not return a new verification token.")
	}

	b.db.Close()
}

// Tests creating a new user with a malformed email.
func TestProcessNewUserWithMalformedEmail(t *testing.T) {
	b := createBackend(t)

	u := www.NewUser{
		Email:    "foobar",
		Password: generateRandomPassword(),
	}

	_, err := b.ProcessNewUser(u)
	assertError(t, err, www.ErrorStatusMalformedEmail)

	b.db.Close()
}

// Tests creating a new user with a malformed password.
func TestProcessNewUserWithMalformedPassword(t *testing.T) {
	b := createBackend(t)

	u := www.NewUser{
		Email:    generateRandomEmail(),
		Password: generateRandomString(www.PolicyPasswordMinChars - 1),
	}

	_, err := b.ProcessNewUser(u)
	assertErrorWithContext(t, err, www.ErrorStatusMalformedPassword,
		[]string{www.PolicyPasswordErrorString})

	b.db.Close()
}

// Tests verifying a non-existing user.
func TestProcessVerifyNewUserWithNonExistingUser(t *testing.T) {
	b := createBackend(t)

	u := www.VerifyNewUser{
		Email:             generateRandomEmail(),
		VerificationToken: generateRandomString(www.VerificationTokenSize),
	}

	err := b.ProcessVerifyNewUser(u)
	assertError(t, err, www.ErrorStatusVerificationTokenInvalid)

	b.db.Close()
}

// Tests verifying a new user with an invalid verification token.
func TestProcessVerifyNewUserWithInvalidToken(t *testing.T) {
	b := createBackend(t)

	u := www.NewUser{
		Email:    generateRandomEmail(),
		Password: generateRandomPassword(),
	}

	_, err := b.ProcessNewUser(u)
	assertSuccess(t, err)

	token, err := util.Random(www.VerificationTokenSize)
	if err != nil {
		t.Fatal(err)
	}

	vu := www.VerifyNewUser{
		Email:             u.Email,
		VerificationToken: hex.EncodeToString(token),
	}

	err = b.ProcessVerifyNewUser(vu)
	assertError(t, err, www.ErrorStatusVerificationTokenInvalid)

	b.db.Close()
}

// Tests logging in with a non-existing user.
func TestProcessLoginWithNonExistingUser(t *testing.T) {
	b := createBackend(t)

	l := www.Login{
		Email:    generateRandomEmail(),
		Password: generateRandomPassword(),
	}

	_, err := b.ProcessLogin(l)
	assertError(t, err, www.ErrorStatusInvalidEmailOrPassword)

	b.db.Close()
}

// Tests logging in with an unverified user.
func TestProcessLoginWithUnverifiedUser(t *testing.T) {
	b := createBackend(t)

	u := www.NewUser{
		Email:    generateRandomEmail(),
		Password: generateRandomPassword(),
	}

	_, err := b.ProcessNewUser(u)
	assertSuccess(t, err)

	l := www.Login(u)
	_, err = b.ProcessLogin(l)
	assertError(t, err, www.ErrorStatusInvalidEmailOrPassword)

	b.db.Close()
}

// Tests the regular login flow without errors: ProcessNewUser,
// ProcessVerifyNewUser, ProcessLogin.
func TestLoginWithVerifiedUser(t *testing.T) {
	b := createBackend(t)
	u := createAndVerifyUser(t, b)

	l := www.Login(u)
	_, err := b.ProcessLogin(l)
	assertSuccess(t, err)

	b.db.Close()
}

// Tests changing a user's password with an incorrect current password
// and a malformed new password.
func TestProcessChangePasswordWithBadPasswords(t *testing.T) {
	b := createBackend(t)
	u := createAndVerifyUser(t, b)

	l := www.Login(u)
	_, err := b.ProcessLogin(l)
	assertSuccess(t, err)

	// Change password with incorrect current password
	cp := www.ChangePassword{
		CurrentPassword: generateRandomPassword(),
		NewPassword:     generateRandomPassword(),
	}
	_, err = b.ProcessChangePassword(u.Email, cp)
	assertError(t, err, www.ErrorStatusInvalidEmailOrPassword)

	// Change password with malformed new password
	cp = www.ChangePassword{
		CurrentPassword: u.Password,
		NewPassword:     generateRandomString(www.PolicyPasswordMinChars - 1),
	}
	_, err = b.ProcessChangePassword(u.Email, cp)
	assertErrorWithContext(t, err, www.ErrorStatusMalformedPassword,
		[]string{www.PolicyPasswordErrorString})

	b.db.Close()
}

// Tests changing a user's password without errors.
func TestProcessChangePassword(t *testing.T) {
	b := createBackend(t)
	u := createAndVerifyUser(t, b)

	l := www.Login(u)
	_, err := b.ProcessLogin(l)
	assertSuccess(t, err)

	// Change password
	cp := www.ChangePassword{
		CurrentPassword: u.Password,
		NewPassword:     generateRandomPassword(),
	}
	_, err = b.ProcessChangePassword(u.Email, cp)
	assertSuccess(t, err)

	// Change password back
	cp = www.ChangePassword{
		CurrentPassword: cp.NewPassword,
		NewPassword:     cp.CurrentPassword,
	}
	_, err = b.ProcessChangePassword(u.Email, cp)
	assertSuccess(t, err)

	b.db.Close()
}

// Tests resetting a user's password with an invalid token.
func TestProcessResetPasswordWithInvalidToken(t *testing.T) {
	b := createBackend(t)
	u := createAndVerifyUser(t, b)

	// Reset password with invalid token
	token, err := util.Random(www.VerificationTokenSize)
	if err != nil {
		t.Fatal(err)
	}

	rp := www.ResetPassword{
		Email:             u.Email,
		VerificationToken: hex.EncodeToString(token),
		NewPassword:       generateRandomPassword(),
	}
	_, err = b.ProcessResetPassword(rp)
	assertError(t, err, www.ErrorStatusVerificationTokenInvalid)

	b.db.Close()
}

// Tests resetting a user's password with an expired token.
func TestProcessResetPasswordWithExpiredToken(t *testing.T) {
	b := createBackend(t)
	u := createAndVerifyUser(t, b)

	b.verificationExpiryTime = time.Duration(100) * time.Nanosecond
	const sleepTime = time.Duration(2) * time.Second

	// Reset password
	rp := www.ResetPassword{
		Email: u.Email,
	}
	rpr, err := b.ProcessResetPassword(rp)
	assertSuccess(t, err)

	// Sleep for a longer amount of time than it takes for the verification token to expire.
	time.Sleep(sleepTime)

	// Reset password verify
	rp = www.ResetPassword{
		Email:             u.Email,
		VerificationToken: rpr.VerificationToken,
		NewPassword:       generateRandomPassword(),
	}
	rpr, err = b.ProcessResetPassword(rp)
	assertError(t, err, www.ErrorStatusVerificationTokenExpired)

	b.db.Close()
}

// Tests resetting a user's password without errors.
func TestProcessResetPassword(t *testing.T) {
	b := createBackend(t)
	u := createAndVerifyUser(t, b)

	// Reset password
	rp := www.ResetPassword{
		Email: u.Email,
	}
	rpr, err := b.ProcessResetPassword(rp)
	assertSuccess(t, err)

	// Reset password verify
	rp = www.ResetPassword{
		Email:             u.Email,
		VerificationToken: rpr.VerificationToken,
		NewPassword:       generateRandomPassword(),
	}
	rpr, err = b.ProcessResetPassword(rp)
	assertSuccess(t, err)

	// Login with new password
	l := www.Login{
		Email:    u.Email,
		Password: rp.NewPassword,
	}
	_, err = b.ProcessLogin(l)
	assertSuccess(t, err)

	b.db.Close()
}
