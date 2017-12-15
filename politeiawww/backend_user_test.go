package main

import (
	"bytes"
	"encoding/hex"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/agl/ed25519"
	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/politeia/politeiad/api/v1/identity"
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

func generateIdentity() (*identity.FullIdentity, error) {
	buf := [32]byte{}
	copy(buf[:], []byte(generateRandomString(8)))
	r := bytes.NewReader(buf[:])
	pub, priv, err := ed25519.GenerateKey(r)
	if err != nil {
		return nil, err
	}
	id := &identity.FullIdentity{}
	copy(id.Public.Key[:], pub[:])
	copy(id.PrivateKey[:], priv[:])
	return id, nil
}

func createNewUserCommandWithIdentity(t *testing.T) (www.NewUser, *identity.FullIdentity) {
	id, err := generateIdentity()
	assertSuccess(t, err)

	return www.NewUser{
		Email:     generateRandomEmail(),
		Password:  generateRandomPassword(),
		PublicKey: hex.EncodeToString(id.Public.Key[:]),
	}, id
}

func createBackend(t *testing.T) *backend {
	dir, err := ioutil.TempDir("", "politeiawww.test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	cfg := &config{
		DataDir:       filepath.Join(dir, "data"),
		PaywallAmount: .1,
		PaywallXpub:   "tpubVobLtToNtTq6TZNw4raWQok35PRPZou53vegZqNubtBTJMMFmuMpWybFCfweJ52N8uZJPZZdHE5SRnBBuuRPfC5jdNstfKjiAs8JtbYG9jx",
		TestNet:       true,
	}

	b, err := NewBackend(cfg)
	if err != nil {
		t.Fatal(err)
	}

	b.params = &chaincfg.TestNet2Params
	b.test = true
	b.inventory = make([]www.ProposalRecord, 0)
	return b
}

func assertSuccess(t *testing.T, err error) {
	if err != nil {
		userErr, ok := err.(www.UserError)
		if ok {
			t.Fatalf("unexpected error code %v\n\n%s",
				userErr.ErrorCode, debug.Stack())
		} else {
			t.Fatalf("unexpected error: %v\n\n%s", err,
				debug.Stack())
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

func createAndVerifyUser(t *testing.T, b *backend) (www.NewUser, *identity.FullIdentity) {
	nu, id := createNewUserCommandWithIdentity(t)
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

	signature := id.SignMessage([]byte(nur.VerificationToken))
	v := www.VerifyNewUser{
		Email:             strings.ToUpper(nu.Email),
		VerificationToken: nur.VerificationToken,
		Signature:         hex.EncodeToString(signature[:]),
	}
	_, err = b.ProcessVerifyNewUser(v)
	assertSuccess(t, err)

	return nu, id
}

// Tests creating a new user with an invalid public key.
func TestProcessNewUserWithInvalidPublicKey(t *testing.T) {
	b := createBackend(t)

	nu := www.NewUser{
		Email:     generateRandomEmail(),
		Password:  generateRandomPassword(),
		PublicKey: generateRandomString(6),
	}

	_, err := b.ProcessNewUser(nu)
	assertError(t, err, www.ErrorStatusInvalidPublicKey)

	b.db.Close()
}

// Tests creating a new user with an existing token which still needs to be verified.
func TestProcessNewUserWithUnverifiedToken(t *testing.T) {
	b := createBackend(t)

	nu, _ := createNewUserCommandWithIdentity(t)
	_, err := b.ProcessNewUser(nu)
	assertSuccess(t, err)

	_, err = b.ProcessNewUser(nu)
	assertSuccess(t, err)

	b.db.Close()
}

// Tests creating a new user which has an expired token.
func TestProcessNewUserWithExpiredToken(t *testing.T) {
	b := createBackend(t)

	b.verificationExpiryTime = time.Duration(100) * time.Nanosecond
	const sleepTime = time.Duration(2) * time.Second

	nu, _ := createNewUserCommandWithIdentity(t)
	reply1, err := b.ProcessNewUser(nu)
	assertSuccess(t, err)

	// Sleep for a longer amount of time than it takes for the verification token to expire.
	time.Sleep(sleepTime)

	reply2, err := b.ProcessNewUser(nu)
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

	nu, _ := createNewUserCommandWithIdentity(t)
	nu.Email = "foobar"

	_, err := b.ProcessNewUser(nu)
	assertError(t, err, www.ErrorStatusMalformedEmail)

	b.db.Close()
}

// Tests creating a new user with a malformed password.
func TestProcessNewUserWithMalformedPassword(t *testing.T) {
	b := createBackend(t)

	nu, _ := createNewUserCommandWithIdentity(t)
	nu.Password = generateRandomString(www.PolicyPasswordMinChars - 1)

	_, err := b.ProcessNewUser(nu)
	assertError(t, err, www.ErrorStatusMalformedPassword)

	b.db.Close()
}

// Tests creating a new user with an invalid signed token.
func TestProcessVerifyNewUserWithInvalidSignature(t *testing.T) {
	b := createBackend(t)

	nu, _ := createNewUserCommandWithIdentity(t)
	nur, err := b.ProcessNewUser(nu)
	assertSuccess(t, err)

	v := www.VerifyNewUser{
		Email:             nu.Email,
		VerificationToken: nur.VerificationToken,
		Signature:         generateRandomString(identity.SignatureSize),
	}
	_, err = b.ProcessVerifyNewUser(v)
	assertError(t, err, www.ErrorStatusInvalidSignature)

	b.db.Close()
}

// Tests verifying a non-existing user.
func TestProcessVerifyNewUserWithNonExistingUser(t *testing.T) {
	b := createBackend(t)

	id, err := generateIdentity()
	assertSuccess(t, err)

	token, err := util.Random(www.VerificationTokenSize)
	assertSuccess(t, err)

	signature := id.SignMessage(token)
	vu := www.VerifyNewUser{
		Email:             generateRandomEmail(),
		VerificationToken: hex.EncodeToString(token),
		Signature:         hex.EncodeToString(signature[:]),
	}

	_, err = b.ProcessVerifyNewUser(vu)
	assertError(t, err, www.ErrorStatusVerificationTokenInvalid)

	b.db.Close()
}

// Tests verifying a new user with an invalid verification token.
func TestProcessVerifyNewUserWithInvalidToken(t *testing.T) {
	b := createBackend(t)

	nu, id := createNewUserCommandWithIdentity(t)
	_, err := b.ProcessNewUser(nu)
	assertSuccess(t, err)

	token, err := util.Random(www.VerificationTokenSize)
	if err != nil {
		t.Fatal(err)
	}

	signature := id.SignMessage(token)
	vu := www.VerifyNewUser{
		Email:             nu.Email,
		VerificationToken: hex.EncodeToString(token),
		Signature:         hex.EncodeToString(signature[:]),
	}

	_, err = b.ProcessVerifyNewUser(vu)
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

	nu, _ := createNewUserCommandWithIdentity(t)
	_, err := b.ProcessNewUser(nu)
	assertSuccess(t, err)

	l := www.Login{
		Email:    nu.Email,
		Password: nu.Password,
	}
	_, err = b.ProcessLogin(l)
	assertError(t, err, www.ErrorStatusInvalidEmailOrPassword)

	b.db.Close()
}

// Tests the regular login flow without errors: ProcessNewUser,
// ProcessVerifyNewUser, ProcessLogin.
func TestLoginWithVerifiedUser(t *testing.T) {
	b := createBackend(t)
	u, id := createAndVerifyUser(t, b)

	l := www.Login{
		Email:    u.Email,
		Password: u.Password,
	}
	lr, err := b.ProcessLogin(l)
	assertSuccess(t, err)

	// Ensure the active public key is the one we provided when signing up.
	expectedPublicKey := hex.EncodeToString(id.Public.Key[:])
	if lr.PublicKey != expectedPublicKey {
		t.Fatalf("expected public key %v, got %v", expectedPublicKey, lr.PublicKey)
	}

	b.db.Close()
}

// Tests changing a user's password with an incorrect current password
// and a malformed new password.
func TestProcessChangePasswordWithBadPasswords(t *testing.T) {
	b := createBackend(t)
	u, _ := createAndVerifyUser(t, b)

	l := www.Login{
		Email:    u.Email,
		Password: u.Password,
	}
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
	assertError(t, err, www.ErrorStatusMalformedPassword)

	b.db.Close()
}

// Tests changing a user's password without errors.
func TestProcessChangePassword(t *testing.T) {
	b := createBackend(t)
	u, _ := createAndVerifyUser(t, b)

	l := www.Login{
		Email:    u.Email,
		Password: u.Password,
	}
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
	u, _ := createAndVerifyUser(t, b)

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
	u, _ := createAndVerifyUser(t, b)

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
	u, _ := createAndVerifyUser(t, b)

	// Reset password
	rp := www.ResetPassword{
		Email: u.Email,
	}
	rpr, err := b.ProcessResetPassword(rp)
	assertSuccess(t, err)

	// Reset password verify
	rp = www.ResetPassword{
		Email:             strings.ToUpper(u.Email),
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
