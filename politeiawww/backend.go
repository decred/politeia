package main

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/bcrypt"

	v1d "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	v1w "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/database"
	"github.com/decred/politeia/politeiawww/database/localdb"
	"github.com/decred/politeia/util"
)

// politeiawww backend construct
type Backend struct {
	db        database.Database
	cfg       *config
	identity  *identity.PublicIdentity
	inventory map[string]v1d.ProposalRecord

	// This is only used for testing.
	verificationExpiryTime time.Duration
}

func newClient() *http.Client {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	return &http.Client{Transport: tr}
}

func (b *Backend) getVerificationExpiryTime() time.Duration {
	if b.verificationExpiryTime != time.Duration(0) {
		return b.verificationExpiryTime
	}
	return time.Duration(v1w.VerificationExpiryHours) * time.Hour
}

func (b *Backend) generateVerificationTokenAndExpiry() ([]byte, int64, error) {
	token, err := util.Random(v1w.VerificationTokenSize)
	if err != nil {
		return nil, 0, err
	}

	expiry := time.Now().Add(b.getVerificationExpiryTime()).Unix()

	return token, expiry, nil
}

// getError returns the error that is embedded in a JSON reply.
func (b *Backend) getError(r io.Reader) (string, error) {
	var e interface{}
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(&e); err != nil {
		return "", err
	}
	m, ok := e.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("Could not decode response")
	}
	rError, ok := m["error"]
	if !ok {
		return "", fmt.Errorf("No error response")
	}
	return fmt.Sprintf("%v", rError), nil
}

func (b *Backend) convertRemoteIdentity(rid v1d.IdentityReply) (*identity.PublicIdentity, error) {
	id, err := hex.DecodeString(rid.Identity)
	if err != nil {
		return nil, err
	}
	if len(id) != identity.IdentitySize {
		return nil, fmt.Errorf("invalid identity size")
	}
	key, err := hex.DecodeString(rid.Key)
	if err != nil {
		return nil, err
	}
	res, err := hex.DecodeString(rid.Response)
	if err != nil {
		return nil, err
	}
	if len(res) != identity.SignatureSize {
		return nil, fmt.Errorf("invalid response size")
	}
	var response [identity.SignatureSize]byte
	copy(response[:], res)

	// Fill out structure
	serverID := identity.PublicIdentity{
		Name: rid.Name,
		Nick: rid.Nick,
	}
	copy(serverID.Key[:], key)
	copy(serverID.Identity[:], id)

	return &serverID, nil
}

func (b *Backend) verifyChallenge(challenge []byte, signature string) error {
	// Verify challenge.
	s, err := hex.DecodeString(signature)
	if err != nil {
		return err
	}
	var sig [identity.SignatureSize]byte
	copy(sig[:], s)
	if !b.identity.VerifyMessage(challenge, sig) {
		return fmt.Errorf("challenge verification failed")
	}

	return nil
}

func (b *Backend) remoteIdentity() (*identity.PublicIdentity, error) {
	challenge, err := util.Random(v1d.ChallengeSize)
	if err != nil {
		return nil, err
	}
	id, err := json.Marshal(v1d.Identity{
		Challenge: hex.EncodeToString(challenge),
	})
	if err != nil {
		return nil, err
	}

	c := newClient()
	r, err := c.Post(b.cfg.DaemonAddress+v1d.IdentityRoute, "application/json",
		bytes.NewReader(id))
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		e, err := b.getError(r.Body)
		if err != nil {
			return nil, fmt.Errorf("%v", r.Status)
		}
		return nil, fmt.Errorf("%v: %v", r.Status, e)
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	var ir v1d.IdentityReply
	err = json.Unmarshal(body, &ir)
	if err != nil {
		return nil, fmt.Errorf("Could node unmarshal IdentityReply: %v",
			err)
	}

	// Convert and verify server identity
	b.identity, err = b.convertRemoteIdentity(ir)
	if err != nil {
		return nil, err
	}

	err = b.verifyChallenge(challenge, ir.Response)
	if err != nil {
		return nil, err
	}

	return b.identity, nil
}

func (b *Backend) remoteInventory() (*v1d.InventoryReply, error) {
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

	c := newClient()
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
		e, err := b.getError(r.Body)
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

	err = b.verifyChallenge(challenge, ir.Response)
	if err != nil {
		return nil, err
	}

	return &ir, nil
}

// LoadIdentity fetches an identity from politeiad if necessary.
func (b *Backend) LoadIdentity() error {
	// Check if an identity already exists.
	if _, err := os.Stat(b.cfg.DaemonIdentityFile); !os.IsNotExist(err) {
		b.identity, err = identity.LoadPublicIdentity(b.cfg.DaemonIdentityFile)
		if err != nil {
			return err
		}

		log.Infof("Identity loaded from: %v", b.cfg.DaemonIdentityFile)
		return nil
	}

	// Fetch remote identity.
	id, err := b.remoteIdentity()
	if err != nil {
		return err
	}

	// Pretty print identity.
	log.Infof("Identity fetched from politeiad")
	log.Infof("FQDN       : %v", id.Name)
	log.Infof("Nick       : %v", id.Nick)
	log.Infof("Key        : %x", id.Key)
	log.Infof("Identity   : %x", id.Identity)
	log.Infof("Fingerprint: %v", id.Fingerprint())

	// Save identity
	err = os.MkdirAll(filepath.Dir(b.cfg.DaemonIdentityFile), 0700)
	if err != nil {
		return err
	}
	err = id.SavePublicIdentity(b.cfg.DaemonIdentityFile)
	if err != nil {
		return err
	}
	log.Infof("Identity saved to: %v", b.cfg.DaemonIdentityFile)

	return nil
}

// LoadInventory fetches the entire inventory of proposals from politeiad
// and caches it.
func (b *Backend) LoadInventory() error {
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
func (b *Backend) ProcessNewUser(u v1w.NewUser) (v1w.NewUserReply, error) {
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
func (b *Backend) ProcessVerifyNewUser(u v1w.VerifyNewUser) error {
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
func (b *Backend) ProcessLogin(l v1w.Login) (*database.User, error) {
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
func (b *Backend) ProcessAllUnvetted() *v1w.GetAllUnvettedReply {
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
func NewBackend(cfg *config) (*Backend, error) {
	// Setup database.
	localdb.UseLogger(localdbLog)
	db, err := localdb.New(cfg.DataDir)
	if err != nil {
		return nil, err
	}

	b := &Backend{
		db:  db,
		cfg: cfg,
	}
	return b, nil
}
