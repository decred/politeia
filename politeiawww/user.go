package main

import (
	"bytes"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"github.com/decred/politeia/politeiad/api/v1/identity"
	www "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/database"
	"github.com/decred/politeia/util"
	"golang.org/x/crypto/bcrypt"
)

// ProcessNewUser creates a new user in the db if it doesn't already
// exist and sets a verification token and expiry; the token must be
// verified before it expires. If the user already exists in the db
// and its token is expired, it generates a new one.
//
// Note that this function always returns a NewUserReply.  The caller shall
// verify error and determine how to return this information upstream.
func (b *backend) ProcessNewUser(u www.NewUser) (*www.NewUserReply, error) {
	var reply www.NewUserReply
	var token []byte
	var expiry int64

	// XXX this function really needs to be cleaned up.

	// Ensure we got a proper pubkey.
	var emptyPK [identity.PublicKeySize]byte
	pk, err := hex.DecodeString(u.PublicKey)
	if err != nil {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidPublicKey,
		}
	}
	if len(pk) != len(emptyPK) ||
		bytes.Equal(pk, emptyPK[:]) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidPublicKey,
		}
	}

	// Check if the user already exists.
	if user, err := b.db.UserGet(u.Email); err == nil {
		// Check if the user is already verified.
		if user.NewUserVerificationToken == nil {
			return &reply, nil
		}

		// Check if the verification token hasn't expired yet.
		if currentTime := time.Now().Unix(); currentTime < user.NewUserVerificationExpiry {
			return &reply, nil
		}

		// Generate a new verification token and expiry.
		token, expiry, err = b.generateVerificationTokenAndExpiry()
		if err != nil {
			return nil, err
		}

		// Add the updated user information to the db.
		user.NewUserVerificationToken = token
		user.NewUserVerificationExpiry = expiry
		err = b.db.UserUpdate(*user)
		if err != nil {
			return nil, err
		}
	} else {
		// Validate the password.
		err = b.validatePassword(u.Password)
		if err != nil {
			return nil, err
		}

		// Hash the user's password.
		hashedPassword, err := b.hashPassword(u.Password)
		if err != nil {
			return nil, err
		}

		// Generate the verification token and expiry.
		token, expiry, err = b.generateVerificationTokenAndExpiry()
		if err != nil {
			return nil, err
		}

		// Add the user and hashed password to the db.
		newUser := database.User{
			Email:          strings.ToLower(u.Email),
			HashedPassword: hashedPassword,
			Admin:          false,
			NewUserVerificationToken:  token,
			NewUserVerificationExpiry: expiry,
			Identities: []database.Identity{{
				Activated: time.Now().Unix(),
			}},
		}
		copy(newUser.Identities[0].Key[:], pk)

		err = b.db.UserNew(newUser)
		if err != nil {
			if err == database.ErrInvalidEmail {
				return nil, www.UserError{
					ErrorCode: www.ErrorStatusMalformedEmail,
				}
			}

			return nil, err
		}
	}

	if !b.test {
		// This is conditional on the email server being setup.
		err := b.emailNewUserVerificationLink(u.Email, hex.EncodeToString(token))
		if err != nil {
			return nil, err
		}
	}

	// Only set the token if email verification is disabled.
	if b.cfg.SMTP == nil {
		reply.VerificationToken = hex.EncodeToString(token)
	}
	return &reply, nil
}

// ProcessVerifyNewUser verifies the token generated for a recently created
// user.  It ensures that the token matches with the input and that the token
// hasn't expired.  On success it returns database user record.
func (b *backend) ProcessVerifyNewUser(u www.VerifyNewUser) (*database.User, error) {
	// Check that the user already exists.
	user, err := b.db.UserGet(u.Email)
	if err != nil {
		if err == database.ErrUserNotFound {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusVerificationTokenInvalid,
			}
		}
		return nil, err
	}

	// Decode the verification token.
	token, err := hex.DecodeString(u.VerificationToken)
	if err != nil {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenInvalid,
		}
	}

	// Check that the verification token matches.
	if !bytes.Equal(token, user.NewUserVerificationToken) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenInvalid,
		}
	}

	// Check that the token hasn't expired.
	if currentTime := time.Now().Unix(); currentTime > user.NewUserVerificationExpiry {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenExpired,
		}
	}

	// Check signature
	sig, err := util.ConvertSignature(u.Signature)
	if err != nil {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}
	var pi *identity.PublicIdentity
	for _, v := range user.Identities {
		if v.Deactivated != 0 {
			continue
		}
		pi, err = identity.PublicIdentityFromBytes(v.Key[:])
		if err != nil {
			return nil, err
		}
	}
	if pi == nil {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusNoPublicKey,
		}
	}
	if !pi.VerifyMessage([]byte(u.VerificationToken), sig) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}

	// Clear out the verification token fields in the db.
	user.NewUserVerificationToken = nil
	user.NewUserVerificationExpiry = 0
	return user, b.db.UserUpdate(*user)
}

// ProcessLogin checks that a user exists, is verified, and has
// the correct password.
func (b *backend) ProcessLogin(l www.Login) (*www.LoginReply, error) {
	// Get user from db.
	user, err := b.db.UserGet(l.Email)
	if err != nil {
		if err == database.ErrUserNotFound {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusInvalidEmailOrPassword,
			}
		}
		return nil, err
	}

	// Check that the user is verified.
	if user.NewUserVerificationToken != nil {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidEmailOrPassword,
		}
	}

	// Check the user's password.
	err = bcrypt.CompareHashAndPassword(user.HashedPassword,
		[]byte(l.Password))
	if err != nil {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidEmailOrPassword,
		}
	}

	activeIdentity, ok := database.ActiveIdentityString(user.Identities)
	if !ok {
		activeIdentity = ""
	}
	return &www.LoginReply{
		IsAdmin:   user.Admin,
		UserID:    strconv.FormatUint(user.ID, 10),
		Email:     user.Email,
		PublicKey: activeIdentity,
	}, nil
}

// ProcessChangePassword checks that the current password matches the one
// in the database, then changes it to the new password.
func (b *backend) ProcessChangePassword(email string, cp www.ChangePassword) (*www.ChangePasswordReply, error) {
	var reply www.ChangePasswordReply

	// Get user from db.
	user, err := b.db.UserGet(email)
	if err != nil {
		return nil, err
	}

	// Check the user's password.
	err = bcrypt.CompareHashAndPassword(user.HashedPassword,
		[]byte(cp.CurrentPassword))
	if err != nil {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidEmailOrPassword,
		}
	}

	// Validate the new password.
	err = b.validatePassword(cp.NewPassword)
	if err != nil {
		return nil, err
	}

	// Hash the user's password.
	hashedPassword, err := b.hashPassword(cp.NewPassword)
	if err != nil {
		return nil, err
	}

	// Add the updated user information to the db.
	user.HashedPassword = hashedPassword
	err = b.db.UserUpdate(*user)
	if err != nil {
		return nil, err
	}

	return &reply, nil
}

// ProcessResetPassword is intended to be called twice; in the first call, an
// email is provided and the function checks if the user exists. If the user exists, it
// generates a verification token and stores it in the database. In the second
// call, the email, verification token and a new password are provided. If everything
// matches, then the user's password is updated in the database.
func (b *backend) ProcessResetPassword(rp www.ResetPassword) (*www.ResetPasswordReply, error) {
	var reply www.ResetPasswordReply

	// Get user from db.
	user, err := b.db.UserGet(rp.Email)
	if err != nil {
		if err == database.ErrInvalidEmail {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusMalformedEmail,
			}
		} else if err == database.ErrUserNotFound {
			return &reply, nil
		}

		return nil, err
	}

	if rp.VerificationToken == "" {
		err = b.emailResetPassword(user, rp, &reply)
	} else {
		err = b.verifyResetPassword(user, rp, &reply)
	}

	if err != nil {
		return nil, err
	}

	return &reply, nil
}

func (b *backend) emailResetPassword(user *database.User, rp www.ResetPassword, rpr *www.ResetPasswordReply) error {
	if user.ResetPasswordVerificationToken != nil {
		currentTime := time.Now().Unix()
		if currentTime < user.ResetPasswordVerificationExpiry {
			// The verification token is present and hasn't expired, so do nothing.
			return nil
		}
	}

	// The verification token isn't present or is present but expired.

	// Generate a new verification token and expiry.
	token, expiry, err := b.generateVerificationTokenAndExpiry()
	if err != nil {
		return err
	}

	// Add the updated user information to the db.
	user.ResetPasswordVerificationToken = token
	user.ResetPasswordVerificationExpiry = expiry
	err = b.db.UserUpdate(*user)
	if err != nil {
		return err
	}

	if !b.test {
		// This is conditional on the email server being setup.
		err := b.emailResetPasswordVerificationLink(rp.Email, hex.EncodeToString(token))
		if err != nil {
			return err
		}
	}

	// Only set the token if email verification is disabled.
	if b.cfg.SMTP == nil {
		rpr.VerificationToken = hex.EncodeToString(token)
	}

	return nil
}

func (b *backend) verifyResetPassword(user *database.User, rp www.ResetPassword, rpr *www.ResetPasswordReply) error {
	// Decode the verification token.
	token, err := hex.DecodeString(rp.VerificationToken)
	if err != nil {
		return www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenInvalid,
		}
	}

	// Check that the verification token matches.
	if !bytes.Equal(token, user.ResetPasswordVerificationToken) {
		return www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenInvalid,
		}
	}

	// Check that the token hasn't expired.
	currentTime := time.Now().Unix()
	if currentTime > user.ResetPasswordVerificationExpiry {
		return www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenExpired,
		}
	}

	// Validate the new password.
	err = b.validatePassword(rp.NewPassword)
	if err != nil {
		return err
	}

	// Hash the new password.
	hashedPassword, err := b.hashPassword(rp.NewPassword)
	if err != nil {
		return err
	}

	// Clear out the verification token fields and set the new password in the db.
	user.ResetPasswordVerificationToken = nil
	user.ResetPasswordVerificationExpiry = 0
	user.HashedPassword = hashedPassword

	return b.db.UserUpdate(*user)
}

// Check an incomming signature against the specified user's pubkey.
func checkSig(user *database.User, signature string, elements ...string) error {
	// Check incoming signature verify(token+string(ProposalStatus))
	sig, err := util.ConvertSignature(signature)
	if err != nil {
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}
	id, ok := database.ActiveIdentity(user.Identities)
	if !ok {
		return www.UserError{
			ErrorCode: www.ErrorStatusNoPublicKey,
		}
	}
	pk, err := identity.PublicIdentityFromBytes(id[:])
	if err != nil {
		return err
	}
	var msg string
	for _, v := range elements {
		msg += v
	}
	if !pk.VerifyMessage([]byte(msg), sig) {
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}
	return nil
}

func (b *backend) validatePassword(password string) error {
	if len(password) < www.PolicyPasswordMinChars {
		return www.UserError{
			ErrorCode: www.ErrorStatusMalformedPassword,
		}
	}

	return nil
}
