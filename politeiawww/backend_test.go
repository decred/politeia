package main

import (
	"encoding/hex"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/decred/politeia/politeiawww/api/v1"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func generateRandomString(n int) string {
	b := make([]byte, 8)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b) + "@example.com"
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

func TestProcessNewUser(t *testing.T) {
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
		t.Error("Token length was %v, expected %v", len(bytes[:]), v1.VerificationTokenSize)
	}

	if err := b.db.Clear(); err != nil {
		t.Error(err)
	}
	b.db.Close()
}

func TestProcessNewUserWithVerify(t *testing.T) {
	b := createBackend(t)

	u := v1.NewUser{
		Email:    generateRandomEmail(),
		Password: generateRandomPassword(),
	}

	reply, err := b.ProcessNewUser(u)
	if err != nil {
		t.Error(err)
	}

	v := v1.VerifyNewUser{
		Email:             u.Email,
		VerificationToken: reply.VerificationToken,
	}
	if err := b.ProcessVerifyNewUser(v); err != nil {
		t.Error(err)
	}

	if err := b.db.Clear(); err != nil {
		t.Error(err)
	}
	b.db.Close()
}

func TestProcessNewUserWithVerifyAndLogin(t *testing.T) {
	b := createBackend(t)

	u := v1.NewUser{
		Email:    generateRandomEmail(),
		Password: generateRandomPassword(),
	}

	reply, err := b.ProcessNewUser(u)
	if err != nil {
		t.Error(err)
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

	if err := b.db.Clear(); err != nil {
		t.Error(err)
	}
	b.db.Close()
}
