package main

import (
	"encoding/hex"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	v1d "github.com/decred/politeia/politeiad/api/v1"
	v1w "github.com/decred/politeia/politeiawww/api/v1"
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
	b.inventory = make([]v1d.ProposalRecord, 0, 0)
	return b
}

func assertSuccess(t *testing.T, err error, status v1w.StatusT) {
	if err != nil {
		t.Fatal(err)
	}
	if status != v1w.StatusSuccess {
		t.Fatalf("unexpected error code %v", status)
	}
}

func assertError(t *testing.T, err error, status, expectedStatus v1w.StatusT) {
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

	u := v1w.NewUser{
		Email:    generateRandomEmail(),
		Password: generateRandomPassword(),
	}

	reply, _, err := b.ProcessNewUser(u)
	assertSuccess(t, err, reply.ErrorCode)

	reply, _, err = b.ProcessNewUser(u)
	assertSuccess(t, err, reply.ErrorCode)

	b.db.Close()
}

// Tests creating a new user which has an expired token.
func TestProcessNewUserWithExpiredToken(t *testing.T) {
	b := createBackend(t)

	b.verificationExpiryTime = time.Duration(100) * time.Nanosecond
	const sleepTime = time.Duration(100) * time.Millisecond

	u := v1w.NewUser{
		Email:    generateRandomEmail(),
		Password: generateRandomPassword(),
	}

	reply1, token1, err := b.ProcessNewUser(u)
	assertSuccess(t, err, reply1.ErrorCode)

	// Sleep for a longer amount of time than it takes for the verification token to expire.
	time.Sleep(sleepTime)

	reply2, token2, err := b.ProcessNewUser(u)
	assertSuccess(t, err, reply2.ErrorCode)

	if token2 == "" {
		t.Fatalf("ProcessNewUser did not return a verification token.")
	}
	if token1 == token2 {
		t.Fatalf("ProcessNewUser did not return a new verification token.")
	}

	b.db.Close()
}

// Tests creating a new user with a malformed email.
func TestProcessNewUserWithMalformedEmail(t *testing.T) {
	b := createBackend(t)

	u := v1w.NewUser{
		Email:    "foobar",
		Password: generateRandomPassword(),
	}

	reply, _, err := b.ProcessNewUser(u)
	assertError(t, err, reply.ErrorCode, v1w.StatusMalformedEmail)

	b.db.Close()
}

// Tests verifying a non-existing user.
func TestProcessVerifyNewUserWithNonExistingUser(t *testing.T) {
	b := createBackend(t)

	u := v1w.VerifyNewUser{
		Email:             generateRandomEmail(),
		VerificationToken: generateRandomString(v1w.VerificationTokenSize),
	}

	status, err := b.ProcessVerifyNewUser(u)
	assertError(t, err, status, v1w.StatusVerificationTokenInvalid)

	b.db.Close()
}

// Tests verifying a new user with an invalid verification token.
func TestProcessVerifyNewUserWithInvalidToken(t *testing.T) {
	b := createBackend(t)

	u := v1w.NewUser{
		Email:    generateRandomEmail(),
		Password: generateRandomPassword(),
	}

	reply, _, err := b.ProcessNewUser(u)
	assertSuccess(t, err, reply.ErrorCode)

	token, err := util.Random(v1w.VerificationTokenSize)
	if err != nil {
		t.Fatal(err)
	}

	vu := v1w.VerifyNewUser{
		Email:             u.Email,
		VerificationToken: hex.EncodeToString(token[:]),
	}

	status, err := b.ProcessVerifyNewUser(vu)
	assertError(t, err, status, v1w.StatusVerificationTokenInvalid)

	b.db.Close()
}

// Tests logging in with a non-existing user.
func TestProcessLoginWithNonExistingUser(t *testing.T) {
	b := createBackend(t)

	l := v1w.Login{
		Email:    generateRandomEmail(),
		Password: generateRandomPassword(),
	}

	reply, err := b.ProcessLogin(l)
	assertError(t, err, reply.ErrorCode, v1w.StatusInvalidEmailOrPassword)

	b.db.Close()
}

// Tests logging in with an unverified user.
func TestProcessLoginWithUnverifiedUser(t *testing.T) {
	b := createBackend(t)

	u := v1w.NewUser{
		Email:    generateRandomEmail(),
		Password: generateRandomPassword(),
	}

	nur, _, err := b.ProcessNewUser(u)
	assertSuccess(t, err, nur.ErrorCode)

	l := v1w.Login{
		Email:    u.Email,
		Password: u.Password,
	}

	lr, err := b.ProcessLogin(l)
	assertError(t, err, lr.ErrorCode, v1w.StatusInvalidEmailOrPassword)

	b.db.Close()
}

// Tests the regular login flow without errors: ProcessNewUser, ProcessVerifyNewUser, ProcessLogin.
func TestLoginWithVerifiedUser(t *testing.T) {
	b := createBackend(t)

	u := v1w.NewUser{
		Email:    generateRandomEmail(),
		Password: generateRandomPassword(),
	}

	nur, token, err := b.ProcessNewUser(u)
	assertSuccess(t, err, nur.ErrorCode)

	bytes, err := hex.DecodeString(token)
	if err != nil {
		t.Fatal(err)
	}

	if len(bytes[:]) != v1w.VerificationTokenSize {
		t.Fatalf("token length was %v, expected %v", len(bytes[:]), v1w.VerificationTokenSize)
	}

	v := v1w.VerifyNewUser{
		Email:             u.Email,
		VerificationToken: token,
	}
	status, err := b.ProcessVerifyNewUser(v)
	assertSuccess(t, err, status)

	l := v1w.Login{
		Email:    u.Email,
		Password: u.Password,
	}
	reply, err := b.ProcessLogin(l)
	assertSuccess(t, err, reply.ErrorCode)

	b.db.Close()
}
