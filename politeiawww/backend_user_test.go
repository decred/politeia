package main

import (
	"encoding/hex"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
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
	return generateRandomString(16)
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
	b.inventory = make([]www.ProposalRecord, 0, 0)
	return b
}

func assertSuccess(t *testing.T, err error, status www.StatusT) {
	if err != nil {
		t.Fatal(err)
	}
	if status != www.StatusSuccess {
		t.Fatalf("unexpected error code %v", status)
	}
}

func assertError(t *testing.T, err error, status, expectedStatus www.StatusT) {
	if err != nil {
		t.Fatal(err)
	}
	if status != expectedStatus {
		t.Fatalf("expected error code %v", expectedStatus)
	}
}

// Tests creating a new user with an existing token which still needs to be verified.
func TestProcessNewUserWithUnverifiedToken(t *testing.T) {
	b := createBackend(t)

	u := www.NewUser{
		Email:    generateRandomEmail(),
		Password: generateRandomPassword(),
	}

	reply, err := b.ProcessNewUser(u)
	assertSuccess(t, err, reply.ErrorCode)

	reply, err = b.ProcessNewUser(u)
	assertSuccess(t, err, reply.ErrorCode)

	b.db.Close()
}

// Tests creating a new user which has an expired token.
func TestProcessNewUserWithExpiredToken(t *testing.T) {
	b := createBackend(t)

	b.verificationExpiryTime = time.Duration(100) * time.Nanosecond
	const sleepTime = time.Duration(100) * time.Millisecond

	u := www.NewUser{
		Email:    generateRandomEmail(),
		Password: generateRandomPassword(),
	}

	reply1, err := b.ProcessNewUser(u)
	assertSuccess(t, err, reply1.ErrorCode)

	// Sleep for a longer amount of time than it takes for the verification token to expire.
	time.Sleep(sleepTime)

	reply2, err := b.ProcessNewUser(u)
	assertSuccess(t, err, reply2.ErrorCode)

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

	reply, err := b.ProcessNewUser(u)
	assertError(t, err, reply.ErrorCode, www.StatusMalformedEmail)

	b.db.Close()
}

// Tests verifying a non-existing user.
func TestProcessVerifyNewUserWithNonExistingUser(t *testing.T) {
	b := createBackend(t)

	u := www.VerifyNewUser{
		Email:             generateRandomEmail(),
		VerificationToken: generateRandomString(www.VerificationTokenSize),
	}

	status, err := b.ProcessVerifyNewUser(u)
	assertError(t, err, status, www.StatusVerificationTokenInvalid)

	b.db.Close()
}

// Tests verifying a new user with an invalid verification token.
func TestProcessVerifyNewUserWithInvalidToken(t *testing.T) {
	b := createBackend(t)

	u := www.NewUser{
		Email:    generateRandomEmail(),
		Password: generateRandomPassword(),
	}

	reply, err := b.ProcessNewUser(u)
	assertSuccess(t, err, reply.ErrorCode)

	token, err := util.Random(www.VerificationTokenSize)
	if err != nil {
		t.Fatal(err)
	}

	vu := www.VerifyNewUser{
		Email:             u.Email,
		VerificationToken: hex.EncodeToString(token[:]),
	}

	status, err := b.ProcessVerifyNewUser(vu)
	assertError(t, err, status, www.StatusVerificationTokenInvalid)

	b.db.Close()
}

// Tests logging in with a non-existing user.
func TestProcessLoginWithNonExistingUser(t *testing.T) {
	b := createBackend(t)

	l := www.Login{
		Email:    generateRandomEmail(),
		Password: generateRandomPassword(),
	}

	reply, err := b.ProcessLogin(l)
	assertError(t, err, reply.ErrorCode, www.StatusInvalidEmailOrPassword)

	b.db.Close()
}

// Tests logging in with an unverified user.
func TestProcessLoginWithUnverifiedUser(t *testing.T) {
	b := createBackend(t)

	u := www.NewUser{
		Email:    generateRandomEmail(),
		Password: generateRandomPassword(),
	}

	nur, err := b.ProcessNewUser(u)
	assertSuccess(t, err, nur.ErrorCode)

	l := www.Login{
		Email:    u.Email,
		Password: u.Password,
	}

	lr, err := b.ProcessLogin(l)
	assertError(t, err, lr.ErrorCode, www.StatusInvalidEmailOrPassword)

	b.db.Close()
}

// Tests the regular login flow without errors: ProcessNewUser,
// ProcessVerifyNewUser, ProcessLogin.
func TestLoginWithVerifiedUser(t *testing.T) {
	b := createBackend(t)

	u := www.NewUser{
		Email:    generateRandomEmail(),
		Password: generateRandomPassword(),
	}

	nur, err := b.ProcessNewUser(u)
	assertSuccess(t, err, nur.ErrorCode)

	bytes, err := hex.DecodeString(nur.VerificationToken)
	if err != nil {
		t.Fatal(err)
	}

	if len(bytes[:]) != www.VerificationTokenSize {
		t.Fatalf("token length was %v, expected %v", len(bytes[:]),
			www.VerificationTokenSize)
	}

	v := www.VerifyNewUser{
		Email:             u.Email,
		VerificationToken: nur.VerificationToken,
	}
	status, err := b.ProcessVerifyNewUser(v)
	assertSuccess(t, err, status)

	l := www.Login{
		Email:    u.Email,
		Password: u.Password,
	}
	reply, err := b.ProcessLogin(l)
	assertSuccess(t, err, reply.ErrorCode)

	b.db.Close()
}
