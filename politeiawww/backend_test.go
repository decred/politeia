package main

import (
	"encoding/hex"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/decred/politeia/politeiawww/api/v1"
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

	b, err := NewBackend(filepath.Join(dir, "data"))
	if err != nil {
		t.Error(err)
	}

	return b
}

// Tests creating a new user with an existing token which still needs to be verified.
func TestProcessNewUserWithUnverifiedToken(t *testing.T) {
	b := createBackend(t)

	u := v1.NewUser{
		Email:    generateRandomEmail(),
		Password: generateRandomPassword(),
	}

	_, err := b.ProcessNewUser(u)
	if err != nil {
		t.Error(err)
	}

	_, err = b.ProcessNewUser(u)
	if err == nil {
		t.Errorf("ProcessNewUser called without error, expected 'user already exists' error")
	}

	b.db.Close()
}

// Tests creating a new user which has an expired token.
func TestProcessNewUserWithExpiredToken(t *testing.T) {
	b := createBackend(t)

	b.verificationExpiryTime = time.Duration(100) * time.Nanosecond
	const sleepTime = time.Duration(100) * time.Millisecond

	u := v1.NewUser{
		Email:    generateRandomEmail(),
		Password: generateRandomPassword(),
	}

	_, err := b.ProcessNewUser(u)
	if err != nil {
		t.Error(err)
	}

	// Sleep for a longer amount of time than it takes for the verification token to expire.
	time.Sleep(sleepTime)

	_, err = b.ProcessNewUser(u)
	if err != nil {
		t.Error(err)
	}

	b.db.Close()
}

// Tests creating a new user with an invalid email.
func TestProcessNewUserWithInvalidEmail(t *testing.T) {
	b := createBackend(t)

	u := v1.NewUser{
		Email:    "foobar",
		Password: generateRandomPassword(),
	}

	_, err := b.ProcessNewUser(u)
	if err == nil {
		t.Errorf("ProcessNewUser called without error, expected 'email not valid' error")
	}

	b.db.Close()
}

// Tests verifying a non-existing user.
func TestProcessVerifyNewUserWithNonExistingUser(t *testing.T) {
	b := createBackend(t)

	u := v1.VerifyNewUser{
		Email:             generateRandomEmail(),
		VerificationToken: generateRandomString(v1.VerificationTokenSize),
	}

	err := b.ProcessVerifyNewUser(u)
	if err == nil {
		t.Errorf("ProcessVerifyNewUser called without error, expected 'user not found' error")
	}

	b.db.Close()
}

// Tests verifying a new user with an invalid verification token.
func TestProcessVerifyNewUserWithInvalidToken(t *testing.T) {
	b := createBackend(t)

	u := v1.NewUser{
		Email:    generateRandomEmail(),
		Password: generateRandomPassword(),
	}

	_, err := b.ProcessNewUser(u)
	if err != nil {
		t.Error(err)
	}

	token, err := util.Random(v1.VerificationTokenSize)
	if err != nil {
		t.Error(err)
	}

	vu := v1.VerifyNewUser{
		Email:             u.Email,
		VerificationToken: hex.EncodeToString(token[:]),
	}

	err = b.ProcessVerifyNewUser(vu)
	if err == nil {
		t.Errorf("ProcessVerifyNewUser called without error, expected 'verification token invalid' error")
	}

	b.db.Close()
}

// Tests logging in with a non-existing user.
func TestProcessLoginWithNonExistingUser(t *testing.T) {
	b := createBackend(t)

	l := v1.Login{
		Email:    generateRandomEmail(),
		Password: generateRandomPassword(),
	}

	err := b.ProcessLogin(l)
	if err == nil {
		t.Errorf("ProcessLogin called without error, expected 'user not found' error")
	}

	b.db.Close()
}

// Tests logging in with an unverified user.
func TestProcessLoginWithUnverifiedUser(t *testing.T) {
	b := createBackend(t)

	u := v1.NewUser{
		Email:    generateRandomEmail(),
		Password: generateRandomPassword(),
	}

	_, err := b.ProcessNewUser(u)
	if err != nil {
		t.Error(err)
	}

	l := v1.Login{
		Email:    u.Email,
		Password: u.Password,
	}

	err = b.ProcessLogin(l)
	if err == nil {
		t.Errorf("ProcessLogin called without error, expected 'user not verified' error")
	}

	b.db.Close()
}

// Tests the regular login flow without errors: ProcessNewUser, ProcessVerifyNewUser, ProcessLogin.
func TestLoginWithVerifiedUser(t *testing.T) {
	b := createBackend(t)

	u := v1.NewUser{
		Email:    generateRandomEmail(),
		Password: generateRandomPassword(),
	}

	reply, err := b.ProcessNewUser(u)
	if err != nil {
		t.Error(err)
	}

	bytes, err := hex.DecodeString(reply.VerificationToken)
	if err != nil {
		t.Error(err)
	}

	if len(bytes[:]) != v1.VerificationTokenSize {
		t.Errorf("token length was %v, expected %v", len(bytes[:]), v1.VerificationTokenSize)
	}

	v := v1.VerifyNewUser{
		Email:             u.Email,
		VerificationToken: reply.VerificationToken,
	}
	if err := b.ProcessVerifyNewUser(v); err != nil {
		t.Error(err)
	}

	l := v1.Login{
		Email:    u.Email,
		Password: u.Password,
	}
	if err := b.ProcessLogin(l); err != nil {
		t.Error(err)
	}

	b.db.Close()
}
