package main

import (
	"bytes"
	"encoding/hex"
	"errors"
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
}

// ProcessNewUser ...
func (b *backend) ProcessNewUser(u v1.NewUser) (v1.NewUserReply, error) {
	var reply v1.NewUserReply

	// XXX fix errors

	// Check if the user already exists.
	if _, err := b.db.UserGet(u.Email); err == nil {
		return reply, errors.New("user already exists")
	}

	// Hash the user's password.
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.Password),
		bcrypt.DefaultCost)
	if err != nil {
		return reply, err
	}

	// Generate the verification token and expiry.
	token, err := util.Random(v1.VerificationTokenSize)
	if err != nil {
		return reply, err
	}
	expiry := time.Now().Add(time.Duration(v1.VerificationExpiryHours) * time.Hour).Unix()

	// Add the user and hashed password to the db.
	user := database.User{
		Email:              u.Email,
		HashedPassword:     hashedPassword,
		Admin:              false,
		VerificationToken:  token,
		VerificationExpiry: expiry,
	}
	err = b.db.UserNew(user)
	if err != nil {
		return reply, err
	}

	// Reply with the verification token.
	reply = v1.NewUserReply{
		VerificationToken: hex.EncodeToString(token[:]),
	}
	return reply, nil
}

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
		panic("tsk tsk")
		return err
	}

	// Check that the token hasn't expired.
	if currentTime := time.Now().Unix(); currentTime > user.VerificationExpiry {
		panic("tsk tsk")
		return err
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

func (b *backend) ProcessLogin(l v1.Login) error {
	// Get user from db.
	user, err := b.db.UserGet(l.Email)
	if err != nil {
		return err
	}

	// Check the user's password.
	err = bcrypt.CompareHashAndPassword(user.HashedPassword,
		[]byte(l.Password))
	if err != nil {
		return err
	}

	return nil
}

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
