package main

import (
	"bytes"
	"encoding/hex"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/agl/ed25519"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	www "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/util"
	"github.com/stretchr/testify/suite"
)

const (
	letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

// UserTestSuite tests the logic concerning users. Inherits the backend setup
// and teardown, as well as all the testify suite methods from BackendTestSuite
type UserTestSuite struct {
	BackendTestSuite
}

func TestUserTestSuite(t *testing.T) {
	suite.Run(t, new(UserTestSuite))
}

// Tests creating a new user with an invalid public key.
func (s *UserTestSuite) TestProcessNewUserWithInvalidPublicKey() {
	nu := www.NewUser{
		Email:     generateRandomEmail(),
		Password:  generateRandomPassword(),
		PublicKey: generateRandomString(6),
	}

	_, err := s.backend.ProcessNewUser(nu)
	s.EqualValues(www.UserError{
		ErrorCode: www.ErrorStatusInvalidPublicKey,
	}, err)
}

// Tests creating a new user with an existing token which still needs to be verified.
func (s *UserTestSuite) TestProcessNewUserWithUnverifiedToken() {
	nu, _, err := createNewUserCommandWithIdentity()
	s.NoError(err)
	s.NotZero(nu)

	_, err = s.backend.ProcessNewUser(nu)
	s.NoError(err)

	_, err = s.backend.ProcessNewUser(nu)
	s.NoError(err)
}

// Tests creating a new user which has an expired token.
func (s *UserTestSuite) TestProcessNewUserWithExpiredToken() {
	s.backend.verificationExpiryTime = time.Duration(100) * time.Nanosecond
	const sleepTime = time.Duration(2) * time.Second

	nu, _, err := createNewUserCommandWithIdentity()
	s.NoError(err)
	s.NotZero(nu)

	reply1, err := s.backend.ProcessNewUser(nu)
	s.NoError(err)
	s.NotNil(reply1)

	// Sleep for a longer amount of time than it takes for the verification token to expire.
	time.Sleep(sleepTime)

	reply2, err := s.backend.ProcessNewUser(nu)
	s.NoError(err)
	s.NotNil(reply2)

	s.NotEmpty(reply2.VerificationToken)
	s.NotEqual(reply1.VerificationToken, reply2.VerificationToken)
}

// Tests creating a new user with a malformed email.
func (s *UserTestSuite) TestProcessNewUserWithMalformedEmail() {
	nu, _, err := createNewUserCommandWithIdentity()
	s.NoError(err)
	s.NotZero(nu)
	nu.Email = "foobar"

	_, err = s.backend.ProcessNewUser(nu)
	s.EqualValues(www.UserError{
		ErrorCode: www.ErrorStatusMalformedEmail,
	}, err)
}

// Tests creating a new user with a malformed password.
func (s *UserTestSuite) TestProcessNewUserWithMalformedPassword() {
	nu, _, err := createNewUserCommandWithIdentity()
	s.NoError(err)
	s.NotZero(nu)

	nu.Password = generateRandomString(www.PolicyPasswordMinChars - 1)

	_, err = s.backend.ProcessNewUser(nu)
	s.EqualValues(www.UserError{
		ErrorCode: www.ErrorStatusMalformedPassword,
	}, err)
}

// Tests creating a new user with an invalid signed token.
func (s *UserTestSuite) TestProcessVerifyNewUserWithInvalidSignature() {
	nu, _, err := createNewUserCommandWithIdentity()
	s.NoError(err)
	s.NotZero(nu)

	nur, err := s.backend.ProcessNewUser(nu)
	s.NoError(err)
	s.NotNil(nur)

	v := www.VerifyNewUser{
		Email:             nu.Email,
		VerificationToken: nur.VerificationToken,
		Signature:         generateRandomString(identity.SignatureSize),
	}
	_, err = s.backend.ProcessVerifyNewUser(v)
	s.EqualValues(www.UserError{
		ErrorCode: www.ErrorStatusInvalidSignature,
	}, err)
}

// Tests verifying a non-existing user.
func (s *UserTestSuite) TestProcessVerifyNewUserWithNonExistingUser() {
	id, err := generateIdentity()
	s.NoError(err)
	s.NotNil(id)

	token, err := util.Random(www.VerificationTokenSize)
	s.NoError(err)
	s.NotZero(token)

	signature := id.SignMessage(token)
	vu := www.VerifyNewUser{
		Email:             generateRandomEmail(),
		VerificationToken: hex.EncodeToString(token),
		Signature:         hex.EncodeToString(signature[:]),
	}

	_, err = s.backend.ProcessVerifyNewUser(vu)
	s.EqualValues(www.UserError{
		ErrorCode: www.ErrorStatusVerificationTokenInvalid,
	}, err)
}

// Tests verifying a new user with an invalid verification token.
func (s *UserTestSuite) TestProcessVerifyNewUserWithInvalidToken() {
	nu, id, err := createNewUserCommandWithIdentity()
	s.NoError(err)
	s.NotNil(id)
	s.NotZero(nu)

	_, err = s.backend.ProcessNewUser(nu)
	s.NoError(err)

	token, err := util.Random(www.VerificationTokenSize)
	s.NoError(err)
	s.NotZero(token)

	signature := id.SignMessage(token)
	vu := www.VerifyNewUser{
		Email:             nu.Email,
		VerificationToken: hex.EncodeToString(token),
		Signature:         hex.EncodeToString(signature[:]),
	}

	_, err = s.backend.ProcessVerifyNewUser(vu)
	s.EqualValues(www.UserError{
		ErrorCode: www.ErrorStatusVerificationTokenInvalid,
	}, err)
}

// Tests logging in with a non-existing user.
func (s *UserTestSuite) TestProcessLoginWithNonExistingUser() {
	l := www.Login{
		Email:    generateRandomEmail(),
		Password: generateRandomPassword(),
	}

	_, err := s.backend.ProcessLogin(l)
	s.EqualValues(www.UserError{
		ErrorCode: www.ErrorStatusInvalidEmailOrPassword,
	}, err)
}

// Tests logging in with an unverified user.
func (s *UserTestSuite) TestProcessLoginWithUnverifiedUser() {
	nu, _, err := createNewUserCommandWithIdentity()
	s.NoError(err)
	s.NotZero(nu)

	_, err = s.backend.ProcessNewUser(nu)
	s.NoError(err)

	l := www.Login{
		Email:    nu.Email,
		Password: nu.Password,
	}
	_, err = s.backend.ProcessLogin(l)
	s.EqualValues(www.UserError{
		ErrorCode: www.ErrorStatusInvalidEmailOrPassword,
	}, err)
}

// Tests the regular login flow without errors: ProcessNewUser,
// ProcessVerifyNewUser, ProcessLogin.
func (s *UserTestSuite) TestLoginWithVerifiedUser() {
	u, id, err := createAndVerifyUser(s.backend)
	s.NoError(err)
	s.NotNil(id)
	s.NotZero(u)

	// login
	l := www.Login{
		Email:    u.Email,
		Password: u.Password,
	}
	lr, err := s.backend.ProcessLogin(l)
	s.NoError(err)
	s.NotNil(lr)

	// Ensure the active public key is the one we provided when signing up.
	expectedPublicKey := hex.EncodeToString(id.Public.Key[:])
	s.Equal(expectedPublicKey, lr.PublicKey)
}

// Tests changing a user's password with an incorrect current password
// and a malformed new password.
func (s *UserTestSuite) TestProcessChangePasswordWithBadPasswords() {
	u, _, err := createAndVerifyUser(s.backend)
	s.NoError(err)
	s.NotZero(u)

	// login
	l := www.Login{
		Email:    u.Email,
		Password: u.Password,
	}
	_, err = s.backend.ProcessLogin(l)
	s.NoError(err)

	// Change password with incorrect current password
	cp := www.ChangePassword{
		CurrentPassword: generateRandomPassword(),
		NewPassword:     generateRandomPassword(),
	}
	_, err = s.backend.ProcessChangePassword(u.Email, cp)
	s.EqualValues(www.UserError{
		ErrorCode: www.ErrorStatusInvalidEmailOrPassword,
	}, err)

	// Change password with malformed new password
	cp = www.ChangePassword{
		CurrentPassword: u.Password,
		NewPassword:     generateRandomString(www.PolicyPasswordMinChars - 1),
	}
	_, err = s.backend.ProcessChangePassword(u.Email, cp)
	s.EqualValues(www.UserError{
		ErrorCode: www.ErrorStatusMalformedPassword,
	}, err)
}

// Tests changing a user's password without errors.
func (s *UserTestSuite) TestProcessChangePassword() {
	u, _, err := createAndVerifyUser(s.backend)
	s.NoError(err)
	s.NotZero(u)

	// login
	l := www.Login{
		Email:    u.Email,
		Password: u.Password,
	}
	_, err = s.backend.ProcessLogin(l)
	s.NoError(err)

	// Change password
	cp := www.ChangePassword{
		CurrentPassword: u.Password,
		NewPassword:     generateRandomPassword(),
	}
	_, err = s.backend.ProcessChangePassword(u.Email, cp)
	s.NoError(err)

	// Change password back
	cp = www.ChangePassword{
		CurrentPassword: cp.NewPassword,
		NewPassword:     cp.CurrentPassword,
	}
	_, err = s.backend.ProcessChangePassword(u.Email, cp)
	s.NoError(err)
}

// Tests resetting a user's password with an invalid token.
func (s *UserTestSuite) TestProcessResetPasswordWithInvalidToken() {
	u, _, err := createAndVerifyUser(s.backend)
	s.NoError(err)
	s.NotZero(u)

	// Reset password with invalid token
	token, err := util.Random(www.VerificationTokenSize)
	s.NoError(err)
	s.NotZero(token)

	rp := www.ResetPassword{
		Email:             u.Email,
		VerificationToken: hex.EncodeToString(token),
		NewPassword:       generateRandomPassword(),
	}
	_, err = s.backend.ProcessResetPassword(rp)
	s.EqualValues(www.UserError{
		ErrorCode: www.ErrorStatusVerificationTokenInvalid,
	}, err)
}

// Tests resetting a user's password with an expired token.
func (s *UserTestSuite) TestProcessResetPasswordWithExpiredToken() {
	u, _, err := createAndVerifyUser(s.backend)
	s.NoError(err)
	s.NotZero(u)

	s.backend.verificationExpiryTime = time.Duration(100) * time.Nanosecond
	const sleepTime = time.Duration(2) * time.Second

	// reset password
	rp := www.ResetPassword{
		Email: u.Email,
	}
	rpr, err := s.backend.ProcessResetPassword(rp)
	s.NoError(err)
	s.NotNil(rpr)

	// sleep for a longer amount of time than it takes for the verification token to expire.
	time.Sleep(sleepTime)

	// reset password verify
	rp = www.ResetPassword{
		Email:             u.Email,
		VerificationToken: rpr.VerificationToken,
		NewPassword:       generateRandomPassword(),
	}
	_, err = s.backend.ProcessResetPassword(rp)
	s.EqualValues(www.UserError{
		ErrorCode: www.ErrorStatusVerificationTokenExpired,
	}, err)
}

// Tests resetting a user's password without errors.
func (s *UserTestSuite) TestProcessResetPassword() {
	// create & verify user
	u, _, err := createAndVerifyUser(s.backend)
	s.NoError(err)
	s.NotZero(u)

	// reset password
	rp := www.ResetPassword{
		Email: u.Email,
	}
	rpr, err := s.backend.ProcessResetPassword(rp)
	s.NoError(err)
	s.NotNil(rpr)

	// reset password verify
	rp = www.ResetPassword{
		Email:             strings.ToUpper(u.Email),
		VerificationToken: rpr.VerificationToken,
		NewPassword:       generateRandomPassword(),
	}
	rpr, err = s.backend.ProcessResetPassword(rp)
	s.NoError(err)
	s.NotNil(rpr)

	// Login with new password
	l := www.Login{
		Email:    u.Email,
		Password: rp.NewPassword,
	}
	_, err = s.backend.ProcessLogin(l)
	s.NoError(err)
}

//@TODO(rgeraldes)
func (s *BackendTestSuite) TestCheckSig() {}

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

func createNewUserCommandWithIdentity() (www.NewUser, *identity.FullIdentity, error) {
	id, err := generateIdentity()
	if err != nil {
		return www.NewUser{}, nil, err
	}

	return www.NewUser{
		Email:     generateRandomEmail(),
		Password:  generateRandomPassword(),
		PublicKey: hex.EncodeToString(id.Public.Key[:]),
	}, id, nil
}

func createAndVerifyUser(backend *backend) (www.NewUser, *identity.FullIdentity, error) {
	nu, id, err := createNewUserCommandWithIdentity()
	if err != nil {
		return www.NewUser{}, nil, err
	}

	nur, err := backend.ProcessNewUser(nu)
	if err != nil {
		return www.NewUser{}, nil, err
	}

	_, err = hex.DecodeString(nur.VerificationToken)
	if err != nil {
		return www.NewUser{}, nil, err
	}

	signature := id.SignMessage([]byte(nur.VerificationToken))
	v := www.VerifyNewUser{
		Email:             strings.ToUpper(nu.Email),
		VerificationToken: nur.VerificationToken,
		Signature:         hex.EncodeToString(signature[:]),
	}
	_, err = backend.ProcessVerifyNewUser(v)
	if err != nil {
		return www.NewUser{}, nil, err
	}

	return nu, id, nil
}
