package main

import (
	"encoding/hex"
	"math/rand"
	"path/filepath"
	"testing"
	
	"github.com/decred/dcrutil"
	"github.com/decred/politeia/politeiawww/api/v1"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

var (
	dataDir = filepath.Join(dcrutil.AppDataDir("politeiawww", false), "tests", "data")
)

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


func TestProcessNewUser(t *testing.T) {
	u := v1.NewUser{
		Email: generateRandomEmail(),
		Password: generateRandomPassword(),
	}

	b, err := NewBackend(dataDir)
	if err != nil {
		t.Error(err)
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
	u := v1.NewUser{
		Email:    generateRandomEmail(),
		Password: generateRandomPassword(),
	}

	b, err := NewBackend(dataDir)
	if err != nil {
		t.Error(err)
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
	u := v1.NewUser{
		Email:    generateRandomEmail(),
		Password: generateRandomPassword(),
	}

	b, err := NewBackend(dataDir)
	if err != nil {
		t.Error(err)
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
