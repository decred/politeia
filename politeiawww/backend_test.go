package main

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/decred/politeia/politeiad/api/v1/identity"
	v1 "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/util"
)

func TestProcessNewUser(t *testing.T) {
	p := newTestPoliteiawww(t)
	defer cleanupTestPoliteiawww(t, p)

	// Create a verified user
	usrVerified, _ := newUser(t, p, false)

	// Create an unverified user with an unexpired verification
	// token. We do this by creating a verified user then manually
	// reseting the user's verification token in the database.
	usrUnexpired, _ := newUser(t, p, false)
	token, expiry, err := p.generateVerificationTokenAndExpiry()
	if err != nil {
		t.Fatalf("%v", err)
	}
	usrUnexpired.NewUserVerificationToken = token
	usrUnexpired.NewUserVerificationExpiry = expiry
	err = p.db.UserUpdate(*usrUnexpired)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Create an unverified user with an expired verification
	// token. We do this by creating a verified user and then
	// manually updating the token and expiration in the database
	// A user with an expired verification token is allowed to
	// send up a new pubkey if they want to update their identity.
	usrExpired, _ := newUser(t, p, false)
	token, _, err = p.generateVerificationTokenAndExpiry()
	if err != nil {
		t.Fatalf("%v", err)
	}
	usrExpired.NewUserVerificationToken = token
	usrExpired.NewUserVerificationExpiry = time.Now().Unix() - 1
	err = p.db.UserUpdate(*usrExpired)
	if err != nil {
		t.Fatalf("%v", err)
	}

	id, err := identity.New()
	if err != nil {
		t.Fatalf("%v", err)
	}
	usrExpiredPublicKey := hex.EncodeToString(id.Public.Key[:])

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
	validPublicKey := hex.EncodeToString(id.Public.Key[:])

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
			_, err := p.ProcessNewUser(v.newUser)
			got := errToStr(err)
			want := errToStr(v.want)
			if got != want {
				t.Errorf("got error %v, want error %v",
					got, want)
			}
		})
	}
}

func TestProcessVerifyNewUser(t *testing.T) {
	p := newTestPoliteiawww(t)
	defer cleanupTestPoliteiawww(t, p)

	// Create a user with a valid, unexpired verification
	// token. We do this by creating a verified user then
	// reseting the token verification fields manually.
	usr, id := newUser(t, p, false)
	tb, expiry, err := p.generateVerificationTokenAndExpiry()
	if err != nil {
		t.Fatalf("%v", err)
	}
	usr.NewUserVerificationToken = tb
	usr.NewUserVerificationExpiry = expiry
	err = p.db.UserUpdate(*usr)
	if err != nil {
		t.Fatalf("%v", err)
	}
	s := id.SignMessage(tb)
	sig := hex.EncodeToString(s[:])
	token := hex.EncodeToString(tb)

	s = id.SignMessage([]byte("intentionally wrong"))
	wrongSig := hex.EncodeToString(s[:])

	// Create a token that does not correspond to a user
	b, _, err := p.generateVerificationTokenAndExpiry()
	wrongToken := hex.EncodeToString(b)

	// Create a user with an expired verification token
	expiredUsr, id := newUser(t, p, false)
	tb, expiry, err = p.generateVerificationTokenAndExpiry()
	if err != nil {
		t.Fatalf("%v", err)
	}
	expiredUsr.NewUserVerificationToken = tb
	expiredUsr.NewUserVerificationExpiry = time.Now().Unix() - 1
	err = p.db.UserUpdate(*expiredUsr)
	if err != nil {
		t.Fatalf("%v", err)
	}
	s = id.SignMessage(tb)
	expiredSig := hex.EncodeToString(s[:])
	expiredToken := hex.EncodeToString(tb)

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
			_, err := p.ProcessVerifyNewUser(v.input)
			got := errToStr(err)
			want := errToStr(v.want)
			if got != want {
				t.Errorf("got error %v, want error %v",
					got, want)
			}
		})
	}
}
