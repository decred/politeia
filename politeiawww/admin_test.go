package main

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/decred/politeia/politeiad/api/v1/identity"
	www "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/database"
)

func createUnverifiedUser(t *testing.T, b *backend) (*database.User, *identity.FullIdentity) {
	nu, id := createNewUserCommandWithIdentity(t)
	nur, err := b.ProcessNewUser(nu)
	assertSuccess(t, err)
	validateVerificationToken(t, nur.VerificationToken)

	user, _ := b.db.UserGet(nu.Email)
	return user, id
}

func verifyUser(t *testing.T, b *backend, user *database.User, identity *identity.FullIdentity, token string) {
	signature := identity.SignMessage([]byte(token))
	v := www.VerifyNewUser{
		Email:             strings.ToUpper(user.Email),
		VerificationToken: token,
		Signature:         hex.EncodeToString(signature[:]),
	}
	_, err := b.ProcessVerifyNewUser(v)
	assertSuccess(t, err)
}

// Tests editing a new user by expiring the verification token.
func TestProcessEditUser(t *testing.T) {
	b := createBackend(t)
	nu, _ := createAndVerifyUser(t, b)
	adminUser, _ := b.db.UserGet(nu.Email)
	user, identity := createUnverifiedUser(t, b)

	// Expire the new user verification token
	eu := www.EditUser{
		UserID: user.ID.String(),
		Action: www.UserEditExpireNewUserVerification,
		Reason: "unit test",
	}
	_, err := b.ProcessEditUser(&eu, adminUser)
	assertSuccess(t, err)

	// Generate a new verification token
	rv := www.ResendVerification{
		Email:     user.Email,
		PublicKey: hex.EncodeToString(identity.Public.Key[:]),
	}
	rvr, err := b.ProcessResendVerification(&rv)
	assertSuccess(t, err)
	validateVerificationToken(t, rvr.VerificationToken)

	verifyUser(t, b, user, identity, rvr.VerificationToken)

	b.db.Close()
}
