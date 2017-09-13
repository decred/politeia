package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/database"
	"github.com/decred/politeia/politeiawww/database/localdb"
	"github.com/decred/politeia/util"
)

// politeiawww backend construct
type backend struct {
	db database.Database

	// This is only used for testing.
	verificationExpiryTime time.Duration
}

func (b *backend) getVerificationExpiryTime() time.Duration {
	if b.verificationExpiryTime != time.Duration(0) {
		return b.verificationExpiryTime
	}
	return time.Duration(v1.VerificationExpiryHours) * time.Hour
}

func (b *backend) generateVerificationTokenAndExpiry() ([]byte, int64, error) {
	token, err := util.Random(v1.VerificationTokenSize)
	if err != nil {
		return nil, 0, err
	}

	expiry := time.Now().Add(b.getVerificationExpiryTime()).Unix()

	return token, expiry, nil
}

// ProcessNewUser creates a new user in the db if it doesn't already
// exist and sets a verification token and expiry; the token must be
// verified before it expires. If the user already exists in the db
// and its token is expired, it generates a new one.
func (b *backend) ProcessNewUser(u v1.NewUser) (v1.NewUserReply, error) {
	var reply v1.NewUserReply
	var token []byte
	var expiry int64

	// Check if the user already exists.
	if user, err := b.db.UserGet(u.Email); err == nil {
		// Check if the user is already verified.
		if user.VerificationToken == nil {
			return reply, errors.New("user already exists")
		}

		// Check if the verification token hasn't expired yet.
		if currentTime := time.Now().Unix(); currentTime < user.VerificationExpiry {
			return reply, fmt.Errorf("user already exists and needs verification")
		}

		// Generate a new verification token and expiry.
		token, expiry, err = b.generateVerificationTokenAndExpiry()
		if err != nil {
			return reply, err
		}

		// Add the updated user information to the db.
		user.VerificationToken = token
		user.VerificationExpiry = expiry
		err = b.db.UserUpdate(*user)
		if err != nil {
			return reply, err
		}
	} else {
		// Hash the user's password.
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.Password),
			bcrypt.DefaultCost)
		if err != nil {
			return reply, err
		}

		// Generate the verification token and expiry.
		token, expiry, err = b.generateVerificationTokenAndExpiry()
		if err != nil {
			return reply, err
		}

		// Add the user and hashed password to the db.
		newUser := database.User{
			Email:              u.Email,
			HashedPassword:     hashedPassword,
			Admin:              false,
			VerificationToken:  token,
			VerificationExpiry: expiry,
		}

		err = b.db.UserNew(newUser)
		if err != nil {
			return reply, err
		}
	}

	// Reply with the verification token.
	reply = v1.NewUserReply{
		VerificationToken: hex.EncodeToString(token[:]),
	}
	return reply, nil
}

// ProcessVerifyNewUser verifies the token generated for a recently created user.
// It ensures that the token matches with the input and that the token hasn't expired.
func (b *backend) ProcessVerifyNewUser(u v1.VerifyNewUser) error {
	// Check that the user already exists.
	user, err := b.db.UserGet(u.Email)
	if err != nil {
		return err
	}

	// Decode the verification token.
	token, err := hex.DecodeString(u.VerificationToken)
	if err != nil {
		return err
	}

	// Check that the verification token matches.
	if !bytes.Equal(token, user.VerificationToken) {
		return fmt.Errorf("verification token invalid")
	}

	// Check that the token hasn't expired.
	if currentTime := time.Now().Unix(); currentTime > user.VerificationExpiry {
		return fmt.Errorf("verification token has expired")
	}

	// Clear out the verification token fields in the db.
	user.VerificationToken = nil
	user.VerificationExpiry = 0
	err = b.db.UserUpdate(*user)
	if err != nil {
		return err
	}

	return nil
}

// ProcessLogin checks that a user exists, is verified, and has
// the correct password.
func (b *backend) ProcessLogin(l v1.Login) error {
	// Get user from db.
	user, err := b.db.UserGet(l.Email)
	if err != nil {
		return v1.ErrInvalidEmailOrPassword
	}

	// Check that the user is verified.
	if user.VerificationToken != nil {
		return errors.New("user not verified")
	}

	// Check the user's password.
	err = bcrypt.CompareHashAndPassword(user.HashedPassword,
		[]byte(l.Password))
	if err != nil {
		return v1.ErrInvalidEmailOrPassword
	}

	return nil
}

// NewBackend creates a new backend context for use in www and tests.
func NewBackend(dataDir string) (*backend, error) {
	// Setup database.
	localdb.UseLogger(localdbLog)
	db, err := localdb.New(dataDir)
	if err != nil {
		return nil, err
	}

	b := &backend{
		db: db,
	}
	return b, nil
}
