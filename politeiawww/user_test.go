// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"reflect"
	"testing"
	"time"

	"github.com/decred/politeia/politeiad/api/v1/identity"
	v1 "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/util"
)

func TestValidatePubkey(t *testing.T) {
	p := newTestPoliteiawww(t)
	defer cleanupTestPoliteiawww(t, p)

	id, err := identity.New()
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Valid public key
	valid := hex.EncodeToString(id.Public.Key[:])

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
		{"valid pubkey", valid, nil},

		{"invalid hexadecimal", invalidHex,
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidPublicKey,
			}},

		{"invalid size", invalidSize,
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidPublicKey,
			}},

		{"empty pubkey", empty,
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidPublicKey,
			}},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			_, err := validatePubkey(v.pubkey)
			got := errToStr(err)
			want := errToStr(v.want)
			if got != want {
				t.Errorf("got error %v, want %v",
					got, want)
			}
		})
	}
}

func TestValidateUsername(t *testing.T) {
	p := newTestPoliteiawww(t)
	defer cleanupTestPoliteiawww(t, p)

	// Username under the min length requirement
	var underMin string
	for i := 0; i < v1.PolicyMinUsernameLength-1; i++ {
		underMin += "0"
	}

	// Username over the max length requirement
	var overMax string
	for i := 0; i < v1.PolicyMaxUsernameLength+1; i++ {
		overMax += "0"
	}

	// Setup tests
	var tests = []struct {
		name     string
		username string
		want     error
	}{
		{"contains uppercase", "Politeiauser",
			v1.UserError{
				ErrorCode: v1.ErrorStatusMalformedUsername,
			}},

		{"leading whitespace", " politeiauser",
			v1.UserError{
				ErrorCode: v1.ErrorStatusMalformedUsername,
			}},

		{"trailing whitespace", "politeiauser ",
			v1.UserError{
				ErrorCode: v1.ErrorStatusMalformedUsername,
			}},

		{"empty", "",
			v1.UserError{
				ErrorCode: v1.ErrorStatusMalformedUsername,
			}},

		{"under min length", underMin,
			v1.UserError{
				ErrorCode: v1.ErrorStatusMalformedUsername,
			}},

		{"over max length", overMax,
			v1.UserError{
				ErrorCode: v1.ErrorStatusMalformedUsername,
			}},

		{"unsupported character", "politeiauser?",
			v1.UserError{
				ErrorCode: v1.ErrorStatusMalformedUsername,
			}},

		{"contains whitespace", "politeia user",
			v1.UserError{
				ErrorCode: v1.ErrorStatusMalformedUsername,
			}},

		{"valid username", "politeiauser", nil},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			err := validateUsername(v.username)
			got := errToStr(err)
			want := errToStr(v.want)
			if got != want {
				t.Errorf("got error %v, want %v",
					got, want)
			}
		})
	}
}

func TestValidatePassword(t *testing.T) {
	p := newTestPoliteiawww(t)
	defer cleanupTestPoliteiawww(t, p)

	// Password under the min length requirement
	var minPass string
	for i := 0; i < v1.PolicyMinPasswordLength-1; i++ {
		minPass += "0"
	}

	// Setup tests
	var tests = []struct {
		name     string
		password string
		want     error
	}{
		{"under min length", minPass,
			v1.UserError{
				ErrorCode: v1.ErrorStatusMalformedPassword,
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

func TestProcessUserDetails(t *testing.T) {
	p := newTestPoliteiawww(t)
	defer cleanupTestPoliteiawww(t, p)

	// Create a new user. This is the UUID that
	// we'll use to test the UserDetails route.
	u, _ := newUser(t, p, false)
	ud := v1.UserDetails{}

	// Test a valid length UUID that does not belong to a user.
	// We can assume that any invalid UUIDs were caught by the
	// user details request handler.
	t.Run("valid UUID with no user", func(t *testing.T) {
		ud.UserID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
		_, err := p.processUserDetails(&ud, false, false)
		got := errToStr(err)
		want := v1.ErrorStatus[v1.ErrorStatusUserNotFound]
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
		name          string         // Test name
		userDetails   v1.UserDetails // User details request
		isCurrentUser bool           // Is a user requesting their own details
		isAdmin       bool           // Is an admin requesting the user details
		want          v1.User        // Wanted user response
		wantMsg       string         // Wanted user response description
	}{
		{"public user details", ud, false, false,
			publicUser, publicUserMsg},

		{"admin requesting user details", ud, false, true,
			fullUser, fullUserMsg},

		{"user requesting their own details", ud, true, false,
			fullUser, fullUserMsg},

		{"admin requesting their own details", ud, true, true,
			fullUser, fullUserMsg},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			udr, err := p.processUserDetails(&v.userDetails,
				v.isCurrentUser, v.isAdmin)
			if err != nil {
				t.Errorf("got error %v, want nil", err)
			}

			if !reflect.DeepEqual(udr.User, v.want) {
				t.Errorf("got unexpected user object, want %v",
					v.wantMsg)
			}
		})
	}
}

func TestProcessEditUser(t *testing.T) {
	p := newTestPoliteiawww(t)
	defer cleanupTestPoliteiawww(t, p)

	// Create a new user. This is the
	// user that we will be editing.
	user, _ := newUser(t, p, false)

	// Setup test cases
	tests := []struct {
		name         string
		notification uint64
		want         []v1.EmailNotificationT
	}{
		{"single notification setting", 0x1,
			[]v1.EmailNotificationT{
				v1.NotificationEmailMyProposalStatusChange,
			}},

		{"multiple notification settings", 0x7,
			[]v1.EmailNotificationT{
				v1.NotificationEmailMyProposalStatusChange,
				v1.NotificationEmailMyProposalVoteStarted,
				v1.NotificationEmailRegularProposalVetted,
			}},

		{"no notification settings", 0x0,
			[]v1.EmailNotificationT{}},

		{"invalid notification setting", 0x100000,
			[]v1.EmailNotificationT{}},
	}

	// Run test cases
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := p.processEditUser(&v1.EditUser{
				EmailNotifications: &test.notification,
			}, user)
			if err != nil {
				t.Errorf("got error %v, want nil", err)
			}

			// Ensure database was updated with
			// correct notification settings.
			u, err := p.db.UserGet(user.Email)
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
				t.Errorf("notification bits got %#x, want %#x",
					bitsGot, bitsWant)
			}
		})
	}
}

func TestProcessNewUser(t *testing.T) {
	p := newTestPoliteiawww(t)
	defer cleanupTestPoliteiawww(t, p)

	// Create a verified user
	usrVerified, _ := newUser(t, p, false)

	// Create an unverified user with an unexpired verification
	// token. We do this by creating a verified user then manually
	// reseting the user's verification token in the database.
	usrUnexpired, _ := newUser(t, p, false)
	token, expiry, err := generateVerificationTokenAndExpiry()
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
	token, _, err = generateVerificationTokenAndExpiry()
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
			_, err := p.processNewUser(v.newUser)
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
	tb, expiry, err := generateVerificationTokenAndExpiry()
	if err != nil {
		t.Fatalf("%v", err)
	}
	usr.NewUserVerificationToken = tb
	usr.NewUserVerificationExpiry = expiry
	err = p.db.UserUpdate(*usr)
	if err != nil {
		t.Fatalf("%v", err)
	}
	token := hex.EncodeToString(tb)
	s := id.SignMessage([]byte(token))
	sig := hex.EncodeToString(s[:])

	s = id.SignMessage([]byte("intentionally wrong"))
	wrongSig := hex.EncodeToString(s[:])

	// Create a token that does not correspond to a user
	b, _, err := generateVerificationTokenAndExpiry()
	if err != nil {
		t.Fatalf("%v", err)
	}
	wrongToken := hex.EncodeToString(b)

	// Create a user with an expired verification token
	expiredUsr, id := newUser(t, p, false)
	tb, _, err = generateVerificationTokenAndExpiry()
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
			_, err := p.processVerifyNewUser(v.input)
			got := errToStr(err)
			want := errToStr(v.want)
			if got != want {
				t.Errorf("got error %v, want error %v",
					got, want)
			}
		})
	}
}
