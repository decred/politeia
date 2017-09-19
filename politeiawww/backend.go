package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"

	v1d "github.com/decred/politeia/politeiad/api/v1"
	v1w "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/database"
	"github.com/decred/politeia/politeiawww/database/localdb"
	"github.com/decred/politeia/util"
)

// politeiawww backend construct
type backend struct {
	db        database.Database
	cfg       *config
	inventory map[string]v1d.ProposalRecord

	// This is only used for testing.
	verificationExpiryTime time.Duration
}

func (b *backend) getVerificationExpiryTime() time.Duration {
	if b.verificationExpiryTime != time.Duration(0) {
		return b.verificationExpiryTime
	}
	return time.Duration(v1w.VerificationExpiryHours) * time.Hour
}

func (b *backend) generateVerificationTokenAndExpiry() ([]byte, int64, error) {
	token, err := util.Random(v1w.VerificationTokenSize)
	if err != nil {
		return nil, 0, err
	}

	expiry := time.Now().Add(b.getVerificationExpiryTime()).Unix()

	return token, expiry, nil
}

func (b *backend) remoteInventory() (*v1d.InventoryReply, error) {
	challenge, err := util.Random(v1d.ChallengeSize)
	if err != nil {
		return nil, err
	}
	inv, err := json.Marshal(v1d.Inventory{
		Challenge:     hex.EncodeToString(challenge),
		IncludeFiles:  false,
		VettedCount:   0,
		BranchesCount: 0,
	})
	if err != nil {
		return nil, err
	}

	c := util.NewClient(b.cfg.SkipTLSVerify)
	req, err := http.NewRequest("POST", b.cfg.DaemonAddress+v1d.InventoryRoute,
		bytes.NewReader(inv))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(b.cfg.RPCUser, b.cfg.RPCPass)
	r, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		e, err := util.GetErrorFromJSON(r.Body)
		if err != nil {
			return nil, fmt.Errorf("%v", r.Status)
		}
		return nil, fmt.Errorf("%v: %v", r.Status, e)
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	var ir v1d.InventoryReply
	err = json.Unmarshal(body, &ir)
	if err != nil {
		return nil, fmt.Errorf("Could node unmarshal InventoryReply: %v",
			err)
	}

	err = util.VerifyChallenge(b.cfg.Identity, challenge, ir.Response)
	if err != nil {
		return nil, err
	}

	return &ir, nil
}

// LoadInventory fetches the entire inventory of proposals from politeiad
// and caches it.
func (b *backend) LoadInventory() error {
	// Fetch remote inventory.
	inv, err := b.remoteInventory()
	if err != nil {
		return fmt.Errorf("LoadInventory: %v", err)
	}

	b.inventory = make(map[string]v1d.ProposalRecord)
	log.Infof("Adding %v vetted proposals to the cache", len(inv.Vetted))
	for _, v := range inv.Vetted {
		b.inventory[v.CensorshipRecord.Token] = v
	}

	log.Infof("Adding %v unvetted proposals to the cache", len(inv.Branches))
	for _, v := range inv.Branches {
		b.inventory[v.CensorshipRecord.Token] = v
	}

	return nil
}

// ProcessNewUser creates a new user in the db if it doesn't already
// exist and sets a verification token and expiry; the token must be
// verified before it expires. If the user already exists in the db
// and its token is expired, it generates a new one.
func (b *backend) ProcessNewUser(u v1w.NewUser) (v1w.NewUserReply, error) {
	var reply v1w.NewUserReply
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
	reply = v1w.NewUserReply{
		VerificationToken: hex.EncodeToString(token[:]),
	}
	return reply, nil
}

// ProcessVerifyNewUser verifies the token generated for a recently created user.
// It ensures that the token matches with the input and that the token hasn't expired.
func (b *backend) ProcessVerifyNewUser(u v1w.VerifyNewUser) error {
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
func (b *backend) ProcessLogin(l v1w.Login) (*database.User, error) {
	// Get user from db.
	user, err := b.db.UserGet(l.Email)
	if err != nil {
		return nil, v1w.ErrInvalidEmailOrPassword
	}

	// Check that the user is verified.
	if user.VerificationToken != nil {
		return nil, errors.New("user not verified")
	}

	// Check the user's password.
	err = bcrypt.CompareHashAndPassword(user.HashedPassword,
		[]byte(l.Password))
	if err != nil {
		return nil, v1w.ErrInvalidEmailOrPassword
	}

	return user, nil
}

// ProcessAllUnvetted returns an array of all unvetted proposals.
func (b *backend) ProcessAllUnvetted() *v1w.GetAllUnvettedReply {
	var proposals []v1d.ProposalRecord
	for _, v := range b.inventory {
		if v.Status == v1d.StatusNotReviewed {
			proposals = append(proposals, v)
		}
	}

	ur := v1w.GetAllUnvettedReply{
		Proposals: proposals,
	}
	return &ur
}

// NewBackend creates a new backend context for use in www and tests.
func NewBackend(cfg *config) (*backend, error) {
	// Setup database.
	localdb.UseLogger(localdbLog)
	db, err := localdb.New(cfg.DataDir)
	if err != nil {
		return nil, err
	}

	b := &backend{
		db:  db,
		cfg: cfg,
	}
	return b, nil
}
