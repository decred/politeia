// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/decred/dcrtime/merkle"
	"github.com/decred/politeia/decredplugin"
	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/api/v1/mime"
	"github.com/decred/politeia/politeiad/cache"
	www "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/util"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const (
	// indexFile contains the file name of the index file
	indexFile = "index.md"

	// mdStream* indicate the metadata stream used for various types
	mdStreamGeneral = 0 // General information for this proposal
	mdStreamChanges = 2 // Changes to record
	// Note that 14 is in use by the decred plugin
	// Note that 15 is in use by the decred plugin

	VersionMDStreamChanges         = 1
	BackendProposalMetadataVersion = 1

	LoginAttemptsToLockUser = 5

	// Route to reset password at GUI
	ResetPasswordGuiRoute = "/password"
)

type MDStreamChanges struct {
	Version             uint             `json:"version"`                       // Version of the struct
	AdminPubKey         string           `json:"adminpubkey"`                   // Identity of the administrator
	NewStatus           pd.RecordStatusT `json:"newstatus"`                     // NewStatus
	StatusChangeMessage string           `json:"statuschangemessage,omitempty"` // Status change message
	Timestamp           int64            `json:"timestamp"`                     // Timestamp of the change
}

type loginReplyWithError struct {
	reply *www.LoginReply
	err   error
}

type BackendProposalMetadata struct {
	Version   uint64 `json:"version"`   // BackendProposalMetadata version
	Timestamp int64  `json:"timestamp"` // Last update of proposal
	Name      string `json:"name"`      // Generated proposal name
	PublicKey string `json:"publickey"` // Key used for signature.
	Signature string `json:"signature"` // Signature of merkle root
}

var (
	validUsername = regexp.MustCompile(createUsernameRegex())

	// MinimumLoginWaitTime is the minimum amount of time to wait before the
	// server sends a response to the client for the login route. This is done
	// to prevent an attacker from executing a timing attack to determine whether
	// the ErrorStatusInvalidEmailOrPassword response is specific to a bad email
	// or bad password.
	MinimumLoginWaitTime = 500 * time.Millisecond
)

// PluginSetting is a structure that holds key/value pairs of a plugin setting.
type PluginSetting struct {
	Key   string // Name of setting
	Value string // Value of setting
}

// Plugin describes a plugin and its settings.
type Plugin struct {
	ID       string          // Identifier
	Version  string          // Version
	Settings []PluginSetting // Settings
}

type VoteDetails struct {
	AuthorizeVote      www.AuthorizeVote      // Authorize vote
	AuthorizeVoteReply www.AuthorizeVoteReply // Authorize vote reply
	StartVote          www.StartVote          // Start vote
	StartVoteReply     www.StartVoteReply     // Start vote reply
}

// encodeBackendProposalMetadata encodes BackendProposalMetadata into a JSON
// byte slice.
func encodeBackendProposalMetadata(md BackendProposalMetadata) ([]byte, error) {
	b, err := json.Marshal(md)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// decodeBackendProposalMetadata decodes a JSON byte slice into a
// BackendProposalMetadata.
func decodeBackendProposalMetadata(payload []byte) (*BackendProposalMetadata, error) {
	var md BackendProposalMetadata

	err := json.Unmarshal(payload, &md)
	if err != nil {
		return nil, err
	}

	return &md, nil
}

// decodeMDStreamChanges decodes a JSON byte slice into a slice of
// MDStreamChanges.
func decodeMDStreamChanges(payload []byte) ([]MDStreamChanges, error) {
	var msc []MDStreamChanges

	d := json.NewDecoder(strings.NewReader(string(payload)))
	for {
		var m MDStreamChanges
		err := d.Decode(&m)
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		msc = append(msc, m)
	}

	return msc, nil
}

// checkPublicKeyAndSignature validates the public key and signature.
func checkPublicKeyAndSignature(u *user.User, publicKey string, signature string, elements ...string) error {
	id, err := checkPublicKey(u, publicKey)
	if err != nil {
		return err
	}

	return checkSignature(id, signature, elements...)
}

// checkPublicKey compares the supplied public key against the one stored in
// the user database. It will return the active identity if there are no errors.
func checkPublicKey(u *user.User, pk string) ([]byte, error) {
	id, ok := user.ActiveIdentity(u.Identities)
	if !ok {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusNoPublicKey,
		}
	}

	if hex.EncodeToString(id[:]) != pk {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidSigningKey,
		}
	}
	return id[:], nil
}

// checkSignature validates an incoming signature against the specified user's pubkey.
func checkSignature(id []byte, signature string, elements ...string) error {
	// Check incoming signature verify(token+string(ProposalStatus))
	sig, err := util.ConvertSignature(signature)
	if err != nil {
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
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

func createUsernameRegex() string {
	var buf bytes.Buffer
	buf.WriteString("^[")

	for _, supportedChar := range www.PolicyUsernameSupportedChars {
		if len(supportedChar) > 1 {
			buf.WriteString(supportedChar)
		} else {
			buf.WriteString(`\` + supportedChar)
		}
	}
	buf.WriteString("]{")
	buf.WriteString(strconv.Itoa(www.PolicyMinUsernameLength) + ",")
	buf.WriteString(strconv.Itoa(www.PolicyMaxUsernameLength) + "}$")

	return buf.String()
}

func (p *politeiawww) getVerificationExpiryTime() time.Duration {
	if p.verificationExpiryTime != time.Duration(0) {
		return p.verificationExpiryTime
	}
	return time.Duration(www.VerificationExpiryHours) * time.Hour
}

func (p *politeiawww) generateVerificationTokenAndExpiry() ([]byte, int64, error) {
	token, err := util.Random(www.VerificationTokenSize)
	if err != nil {
		return nil, 0, err
	}

	expiry := time.Now().Add(p.getVerificationExpiryTime()).Unix()

	return token, expiry, nil
}

// checkUserIsLocked checks if a user is locked after many login attempts
func checkUserIsLocked(failedLoginAttempts uint64) bool {
	return failedLoginAttempts >= LoginAttemptsToLockUser
}

func (p *politeiawww) getUserIDByPubKey(pubkey string) (string, bool) {
	p.RLock()
	defer p.RUnlock()

	userID, ok := p.userPubkeys[pubkey]
	return userID, ok
}

// hashPassword hashes the given password string with the default bcrypt cost
// or the minimum cost if the test flag is set to speed up running tests.
func (p *politeiawww) hashPassword(password string) ([]byte, error) {
	if p.test {
		return bcrypt.GenerateFromPassword([]byte(password),
			bcrypt.MinCost)
	}
	return bcrypt.GenerateFromPassword([]byte(password),
		bcrypt.DefaultCost)
}

// getUsernameById returns the username given its id. If the id is invalid,
// it returns an empty string.
func (p *politeiawww) getUsernameById(userIdStr string) string {
	userId, err := uuid.Parse(userIdStr)
	if err != nil {
		return ""
	}

	u, err := p.db.UserGetById(userId)
	if err != nil {
		return ""
	}

	return u.Username
}

func (p *politeiawww) login(l *www.Login) loginReplyWithError {
	// Get user from db.
	u, err := p.db.UserGet(l.Email)
	if err != nil {
		if err == user.ErrUserNotFound {
			log.Debugf("Login failure for %v: user not found in database",
				l.Email)
			return loginReplyWithError{
				reply: nil,
				err: www.UserError{
					ErrorCode: www.ErrorStatusInvalidEmailOrPassword,
				},
			}
		}

		return loginReplyWithError{
			reply: nil,
			err:   err,
		}
	}

	// Check the user's password.
	err = bcrypt.CompareHashAndPassword(u.HashedPassword,
		[]byte(l.Password))
	if err != nil {
		if !checkUserIsLocked(u.FailedLoginAttempts) {
			u.FailedLoginAttempts++
			err := p.db.UserUpdate(*u)
			if err != nil {
				return loginReplyWithError{
					reply: nil,
					err:   err,
				}
			}

			// Check if the user is locked again so we can send an
			// email.
			if checkUserIsLocked(u.FailedLoginAttempts) && !p.test {
				// This is conditional on the email server
				// being setup.
				err := p.emailUserLocked(u.Email)
				if err != nil {
					return loginReplyWithError{
						reply: nil,
						err:   err,
					}
				}
			}
		}

		log.Debugf("Login failure for %v: incorrect password",
			l.Email)
		return loginReplyWithError{
			reply: nil,
			err: www.UserError{
				ErrorCode: www.ErrorStatusInvalidEmailOrPassword,
			},
		}
	}

	// Check that the user is verified.
	if u.NewUserVerificationToken != nil {
		log.Debugf("Login failure for %v: user not yet verified",
			l.Email)
		return loginReplyWithError{
			reply: nil,
			err: www.UserError{
				ErrorCode: www.ErrorStatusEmailNotVerified,
			},
		}
	}

	// Check if the user account is deactivated.
	if u.Deactivated {
		log.Debugf("Login failure for %v: user deactivated", l.Email)
		return loginReplyWithError{
			reply: nil,
			err: www.UserError{
				ErrorCode: www.ErrorStatusUserDeactivated,
			},
		}
	}

	// Check if user is locked due to too many login attempts
	if checkUserIsLocked(u.FailedLoginAttempts) {
		log.Debugf("Login failure for %v: user locked",
			l.Email)
		return loginReplyWithError{
			reply: nil,
			err: www.UserError{
				ErrorCode: www.ErrorStatusUserLocked,
			},
		}
	}

	lastLoginTime := u.LastLoginTime
	u.FailedLoginAttempts = 0
	u.LastLoginTime = time.Now().Unix()
	err = p.db.UserUpdate(*u)
	if err != nil {
		return loginReplyWithError{
			reply: nil,
			err:   err,
		}
	}
	reply, err := p.CreateLoginReply(u, lastLoginTime)
	return loginReplyWithError{
		reply: reply,
		err:   err,
	}
}

// initUserPubkeys initializes the userPubkeys map with all the pubkey-userid
// associations that are found in the database.
//
// This function must be called WITHOUT the lock held.
func (p *politeiawww) initUserPubkeys() error {
	p.Lock()
	defer p.Unlock()

	return p.db.AllUsers(func(u *user.User) {
		userId := u.ID.String()
		for _, v := range u.Identities {
			key := hex.EncodeToString(v.Key[:])
			p.userPubkeys[key] = userId
		}
	})
}

// setUserPubkeyAssociaton associates a public key with a user id in
// the userPubkeys cache.
//
// This function must be called WITHOUT the lock held.
func (p *politeiawww) setUserPubkeyAssociaton(u *user.User, publicKey string) {
	p.Lock()
	defer p.Unlock()

	userID := u.ID.String()
	p.userPubkeys[publicKey] = userID
}

// removeUserPubkeyAssociaton removes a public key from the
// userPubkeys cache.
//
// This function must be called WITHOUT the lock held.
func (p *politeiawww) removeUserPubkeyAssociaton(u *user.User, publicKey string) {
	p.Lock()
	defer p.Unlock()

	delete(p.userPubkeys, publicKey)
}

func (p *politeiawww) initCommentScores() error {
	log.Tracef("initCommentScores")

	// Fetch decred plugin inventory from cache
	ir, err := p.decredInventory()
	if err != nil {
		return fmt.Errorf("decredInventory: %v", err)
	}

	// XXX this could be done much more efficiently since we
	// already have all of the like comments in the inventory
	// repsonse, but re-using the updateCommentScore function is
	// simplier. This only gets run on startup so I'm not that
	// worried about performance for right now.
	for _, v := range ir.Comments {
		_, err := p.updateCommentScore(v.Token, v.CommentID)
		if err != nil {
			return fmt.Errorf("updateCommentScore: %v", err)
		}
	}

	return nil
}

func (p *politeiawww) validatePubkeyIsUnique(publicKey string, u *user.User) error {
	p.RLock()
	userIDStr, ok := p.userPubkeys[publicKey]
	p.RUnlock()
	if !ok {
		return nil
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return err
	}

	if u != nil && u.ID == userID {
		return nil
	}

	return www.UserError{
		ErrorCode: www.ErrorStatusDuplicatePublicKey,
	}
}

func validateProposal(np www.NewProposal, u *user.User) error {
	log.Tracef("validateProposal")

	// Obtain signature
	sig, err := util.ConvertSignature(np.Signature)
	if err != nil {
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}

	// Verify public key
	id, err := checkPublicKey(u, np.PublicKey)
	if err != nil {
		return err
	}

	pk, err := identity.PublicIdentityFromBytes(id[:])
	if err != nil {
		return err
	}

	// Check for at least 1 markdown file with a non-empty payload.
	if len(np.Files) == 0 || np.Files[0].Payload == "" {
		return www.UserError{
			ErrorCode: www.ErrorStatusProposalMissingFiles,
		}
	}

	// verify if there are duplicate names
	filenames := make(map[string]int, len(np.Files))
	// Check that the file number policy is followed.
	var (
		numMDs, numImages, numIndexFiles      int
		mdExceedsMaxSize, imageExceedsMaxSize bool
		hashes                                []*[sha256.Size]byte
	)
	for _, v := range np.Files {
		filenames[v.Name]++
		var (
			data []byte
			err  error
		)
		if strings.HasPrefix(v.MIME, "image/") {
			numImages++
			data, err = base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				return err
			}
			if len(data) > www.PolicyMaxImageSize {
				imageExceedsMaxSize = true
			}
		} else {
			numMDs++

			if v.Name == indexFile {
				numIndexFiles++
			}

			data, err = base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				return err
			}
			if len(data) > www.PolicyMaxMDSize {
				mdExceedsMaxSize = true
			}
		}

		// Append digest to array for merkle root calculation
		digest := util.Digest(data)
		var d [sha256.Size]byte
		copy(d[:], digest)
		hashes = append(hashes, &d)
	}

	// verify duplicate file names
	if len(np.Files) > 1 {
		var repeated []string
		for name, count := range filenames {
			if count > 1 {
				repeated = append(repeated, name)
			}
		}
		if len(repeated) > 0 {
			return www.UserError{
				ErrorCode:    www.ErrorStatusProposalDuplicateFilenames,
				ErrorContext: repeated,
			}
		}
	}

	// we expect one index file
	if numIndexFiles == 0 {
		return www.UserError{
			ErrorCode:    www.ErrorStatusProposalMissingFiles,
			ErrorContext: []string{indexFile},
		}
	}

	if numMDs > www.PolicyMaxMDs {
		return www.UserError{
			ErrorCode: www.ErrorStatusMaxMDsExceededPolicy,
		}
	}

	if numImages > www.PolicyMaxImages {
		return www.UserError{
			ErrorCode: www.ErrorStatusMaxImagesExceededPolicy,
		}
	}

	if mdExceedsMaxSize {
		return www.UserError{
			ErrorCode: www.ErrorStatusMaxMDSizeExceededPolicy,
		}
	}

	if imageExceedsMaxSize {
		return www.UserError{
			ErrorCode: www.ErrorStatusMaxImageSizeExceededPolicy,
		}
	}

	// proposal title validation
	name, err := getProposalName(np.Files)
	if err != nil {
		return err
	}
	if !util.IsValidProposalName(name) {
		return www.UserError{
			ErrorCode:    www.ErrorStatusProposalInvalidTitle,
			ErrorContext: []string{util.CreateProposalNameRegex()},
		}
	}

	// Note that we need validate the string representation of the merkle
	mr := merkle.Root(hashes)
	if !pk.VerifyMessage([]byte(hex.EncodeToString(mr[:])), sig) {
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}

	return nil
}

func setNewUserVerificationAndIdentity(u *user.User, token []byte, expiry int64, includeResend bool, pk []byte) {
	u.NewUserVerificationToken = token
	u.NewUserVerificationExpiry = expiry
	if includeResend {
		// This field is used to support requesting another registration email
		// quickly, without having to wait the full email-spam-prevention
		// period.
		u.ResendNewUserVerificationExpiry = expiry
	}
	u.Identities = []user.Identity{{
		Activated: time.Now().Unix(),
	}}
	copy(u.Identities[0].Key[:], pk)
}

func (p *politeiawww) emailResetPassword(u *user.User, rp www.ResetPassword, rpr *www.ResetPasswordReply) error {
	if u.ResetPasswordVerificationToken != nil {
		if u.ResetPasswordVerificationExpiry > time.Now().Unix() {
			// The verification token is present and hasn't expired, so do nothing.
			return nil
		}
	}

	// The verification token isn't present or is present but expired.

	// Generate a new verification token and expiry.
	token, expiry, err := p.generateVerificationTokenAndExpiry()
	if err != nil {
		return err
	}

	// Add the updated user information to the db.
	u.ResetPasswordVerificationToken = token
	u.ResetPasswordVerificationExpiry = expiry
	err = p.db.UserUpdate(*u)
	if err != nil {
		return err
	}

	if !p.test {
		// This is conditional on the email server being setup.
		err := p.emailResetPasswordVerificationLink(rp.Email, hex.EncodeToString(token))
		if err != nil {
			return err
		}
	}

	// Only set the token if email verification is disabled.
	if p.smtp.disabled {
		rpr.VerificationToken = hex.EncodeToString(token)
	}

	return nil
}

func (p *politeiawww) verifyResetPassword(u *user.User, rp www.ResetPassword, rpr *www.ResetPasswordReply) error {
	// Decode the verification token.
	token, err := hex.DecodeString(rp.VerificationToken)
	if err != nil {
		log.Debugf("VerifyResetPassword failure for %v: verification token "+
			"could not be decoded: %v", rp.Email, err)
		return www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenInvalid,
		}
	}

	// Check that the verification token matches.
	if !bytes.Equal(token, u.ResetPasswordVerificationToken) {
		log.Debugf("VerifyResetPassword failure for %v: verification token doesn't "+
			"match, expected %v", rp.Email,
			u.ResetPasswordVerificationToken)
		return www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenInvalid,
		}
	}

	// Check that the token hasn't expired.
	if u.ResetPasswordVerificationExpiry < time.Now().Unix() {
		log.Debugf("VerifyResetPassword failure for %v: verification token "+
			"not expired yet", rp.Email)
		return www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenExpired,
		}
	}

	// Validate the new password.
	err = validatePassword(rp.NewPassword)
	if err != nil {
		return err
	}

	// Hash the new password.
	hashedPassword, err := p.hashPassword(rp.NewPassword)
	if err != nil {
		return err
	}

	// Clear out the verification token fields, set the new password in the db,
	// and unlock account
	u.ResetPasswordVerificationToken = nil
	u.ResetPasswordVerificationExpiry = 0
	u.HashedPassword = hashedPassword
	u.FailedLoginAttempts = 0

	return p.db.UserUpdate(*u)
}

func (p *politeiawww) CreateLoginReply(u *user.User, lastLoginTime int64) (*www.LoginReply, error) {
	activeIdentity, ok := user.ActiveIdentityString(u.Identities)
	if !ok {
		activeIdentity = ""
	}

	reply := www.LoginReply{
		IsAdmin:         u.Admin,
		UserID:          u.ID.String(),
		Email:           u.Email,
		Username:        u.Username,
		PublicKey:       activeIdentity,
		PaywallTxID:     u.NewUserPaywallTx,
		ProposalCredits: ProposalCreditBalance(u),
		LastLoginTime:   lastLoginTime,
	}

	if !p.HasUserPaid(u) {
		err := p.GenerateNewUserPaywall(u)
		if err != nil {
			return nil, err
		}

		reply.PaywallAddress = u.NewUserPaywallAddress
		reply.PaywallAmount = u.NewUserPaywallAmount
		reply.PaywallTxNotBefore = u.NewUserPaywallTxNotBefore
	}

	return &reply, nil
}

// ProcessNewUser creates a new user in the db if it doesn't already
// exist and sets a verification token and expiry; the token must be
// verified before it expires. If the user already exists in the db
// and its token is expired, it generates a new one.
//
// Note that this function always returns a NewUserReply.  The caller shall
// verify error and determine how to return this information upstream.
func (p *politeiawww) ProcessNewUser(u www.NewUser) (*www.NewUserReply, error) {
	var (
		reply  www.NewUserReply
		token  []byte
		expiry int64
	)

	existingUser, err := p.db.UserGet(u.Email)
	switch err {
	case nil:
		// User exists
		// Check if the user is already verified.
		if existingUser.NewUserVerificationToken == nil {
			log.Debugf("ProcessNewUser: user is already verified")
			return &reply, nil
		}

		// Check if the verification token is expired. If the token is
		// not expired then we simply return. If the token is expired
		// then we treat this request as a standard NewUser request. A
		// new token is emailed to the user and the database is updated.
		// The user is allowed to use a new pubkey if they want to update
		// their identity.
		if existingUser.NewUserVerificationExpiry > time.Now().Unix() {
			log.Debugf("ProcessNewUser: user is unverified and " +
				"verification token has not yet expired")
			return &reply, nil
		}
	case user.ErrUserNotFound:
		// Doesn't exist, create new user.
	default:
		// All other errors
		return nil, err
	}

	// Ensure we got a proper pubkey.
	pk, err := validatePubkey(u.PublicKey)
	if err != nil {
		return nil, err
	}

	// Format and validate the username.
	username := formatUsername(u.Username)
	err = validateUsername(username)
	if err != nil {
		return nil, err
	}

	// Validate the password.
	err = validatePassword(u.Password)
	if err != nil {
		return nil, err
	}

	// Validate that the pubkey isn't already taken.
	err = p.validatePubkeyIsUnique(u.PublicKey, existingUser)
	if err != nil {
		return nil, err
	}

	// Hash the user's password.
	hashedPassword, err := p.hashPassword(u.Password)
	if err != nil {
		return nil, err
	}

	// Generate the verification token and expiry.
	token, expiry, err = p.generateVerificationTokenAndExpiry()
	if err != nil {
		return nil, err
	}

	// Create a new database user with the provided information.
	newUser := user.User{
		Email:          strings.ToLower(u.Email),
		Username:       username,
		HashedPassword: hashedPassword,
		Admin:          false,
	}
	setNewUserVerificationAndIdentity(&newUser, token, expiry, false, pk)

	if !p.test {
		// Try to email the verification link first; if it fails, then
		// the new user won't be created.
		//
		// This is conditional on the email server being setup.
		err := p.emailNewUserVerificationLink(u.Email, hex.EncodeToString(token), u.Username)
		if err != nil {
			log.Errorf("Email new user verification link failed %v, %v", u.Email, err)
			return &reply, nil
		}
	}

	// Check if the user already exists.
	if existingUser != nil {
		existingPublicKey := hex.EncodeToString(existingUser.Identities[0].Key[:])
		p.removeUserPubkeyAssociaton(existingUser, existingPublicKey)

		// Update the user in the db.
		newUser.ID = existingUser.ID
		err = p.db.UserUpdate(newUser)
	} else {
		// Save the new user in the db.
		err = p.db.UserNew(newUser)
	}

	// Error handling for the db write.
	if err != nil {
		if err == user.ErrInvalidEmail {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusMalformedEmail,
			}
		}

		return nil, err
	}

	// Get user that we just inserted so we can use their numerical user
	// ID (N) to derive the Nth paywall address from the paywall extended
	// public key.
	//
	// Even if existingUser is non-nil, this will bring it up-to-date
	// with the new information inserted via newUser.
	existingUser, err = p.db.UserGet(newUser.Email)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve account info for %v: %v",
			newUser.Email, err)
	}

	// Associate the user id with the new public key.
	p.setUserPubkeyAssociaton(existingUser, u.PublicKey)

	// Derive paywall information for this user if the paywall is enabled.
	err = p.GenerateNewUserPaywall(existingUser)
	if err != nil {
		return nil, err
	}

	// Only set the token if email verification is disabled.
	if p.smtp.disabled {
		reply.VerificationToken = hex.EncodeToString(token)
	}

	log.Debugf("New user created: %v", u.Username)

	return &reply, nil
}

// ProcessVerifyNewUser verifies the token generated for a recently created
// user.  It ensures that the token matches with the input and that the token
// hasn't expired.  On success it returns database user record.
func (p *politeiawww) ProcessVerifyNewUser(usr www.VerifyNewUser) (*user.User, error) {
	// Check that the user already exists.
	u, err := p.db.UserGet(usr.Email)
	if err != nil {
		if err == user.ErrUserNotFound {
			log.Debugf("VerifyNewUser failure for %v: user not found",
				usr.Email)
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusVerificationTokenInvalid,
			}
		}
		return nil, err
	}

	// Decode the verification token.
	token, err := hex.DecodeString(usr.VerificationToken)
	if err != nil {
		log.Debugf("VerifyNewUser failure for %v: verification token could "+
			"not be decoded: %v", u.Email, err)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenInvalid,
		}
	}

	// Check that the verification token matches.
	if !bytes.Equal(token, u.NewUserVerificationToken) {
		log.Debugf("VerifyNewUser: wrong token for user %v "+
			"got %v, want %v", u.Email, hex.EncodeToString(token),
			hex.EncodeToString(u.NewUserVerificationToken))
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenInvalid,
		}
	}

	// Check that the token hasn't expired.
	if time.Now().Unix() > u.NewUserVerificationExpiry {
		log.Debugf("VerifyNewUser failure for %v: verification token expired",
			u.Email)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenExpired,
		}
	}

	// Check signature
	sig, err := util.ConvertSignature(usr.Signature)
	if err != nil {
		log.Debugf("VerifyNewUser failure for %v: signature could not be "+
			"decoded: %v", u.Email, err)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}
	var pi *identity.PublicIdentity
	for _, v := range u.Identities {
		if v.Deactivated != 0 {
			continue
		}
		pi, err = identity.PublicIdentityFromBytes(v.Key[:])
		if err != nil {
			return nil, err
		}
	}
	if pi == nil {
		log.Debugf("VerifyNewUser failure for %v: no public key",
			u.Email)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusNoPublicKey,
		}
	}
	if !pi.VerifyMessage(token, sig) {
		log.Debugf("VerifyNewUser failure for %v: signature doesn't match "+
			"(pubkey: %v)", u.Email, pi.String())
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}

	// Clear out the verification token fields in the db.
	u.NewUserVerificationToken = nil
	u.NewUserVerificationExpiry = 0
	u.ResendNewUserVerificationExpiry = 0
	err = p.db.UserUpdate(*u)
	if err != nil {
		return nil, err
	}

	p.addUserToPaywallPoolLock(u, paywallTypeUser)

	return u, nil
}

// ProcessResendVerification resends a new user verification email if the
// user exists and his verification token is expired.
func (p *politeiawww) ProcessResendVerification(rv *www.ResendVerification) (*www.ResendVerificationReply, error) {
	rvr := www.ResendVerificationReply{}

	// Get user from db.
	u, err := p.db.UserGet(rv.Email)
	if err != nil {
		if err == user.ErrUserNotFound {
			log.Debugf("ResendVerification failure for %v: user not found",
				rv.Email)
			return &rvr, nil
		}
		return nil, err
	}

	// Don't do anything if the user is already verified or the token hasn't
	// expired yet.
	if u.NewUserVerificationToken == nil {
		log.Debugf("ResendVerification failure for %v: user already verified",
			rv.Email)
		return &rvr, nil
	}

	if u.ResendNewUserVerificationExpiry > time.Now().Unix() {
		log.Debugf("ResendVerification failure for %v: verification token "+
			"not expired yet", rv.Email)
		return &rvr, nil
	}

	// Ensure we got a proper pubkey.
	pk, err := validatePubkey(rv.PublicKey)
	if err != nil {
		return nil, err
	}

	// Validate that the pubkey isn't already taken.
	err = p.validatePubkeyIsUnique(rv.PublicKey, u)
	if err != nil {
		return nil, err
	}

	// Generate the verification token and expiry.
	token, expiry, err := p.generateVerificationTokenAndExpiry()
	if err != nil {
		return nil, err
	}

	// Remove the original pubkey from the cache.
	existingPublicKey := hex.EncodeToString(u.Identities[0].Key[:])
	p.removeUserPubkeyAssociaton(u, existingPublicKey)

	// Set a new verificaton token and identity.
	setNewUserVerificationAndIdentity(u, token, expiry, true, pk)

	// Associate the user id with the new identity.
	p.setUserPubkeyAssociaton(u, rv.PublicKey)

	// Update the user in the db.
	err = p.db.UserUpdate(*u)
	if err != nil {
		return nil, err
	}

	if !p.test {
		// This is conditional on the email server being setup.
		err := p.emailNewUserVerificationLink(u.Email,
			hex.EncodeToString(token), u.Username)
		if err != nil {
			return nil, err
		}
	}

	// Only set the token if email verification is disabled.
	if p.smtp.disabled {
		rvr.VerificationToken = hex.EncodeToString(token)
	}
	return &rvr, nil
}

// ProcessUpdateUserKey sets a verification token and expiry to allow the user to
// update his key pair; the token must be verified before it expires. If the
// token is already set and is expired, it generates a new one.
func (p *politeiawww) ProcessUpdateUserKey(usr *user.User, u www.UpdateUserKey) (*www.UpdateUserKeyReply, error) {
	var reply www.UpdateUserKeyReply
	var token []byte
	var expiry int64

	// Ensure we got a proper pubkey.
	pk, err := validatePubkey(u.PublicKey)
	if err != nil {
		return nil, err
	}

	// Validate that the pubkey isn't already taken.
	err = p.validatePubkeyIsUnique(u.PublicKey, nil)
	if err != nil {
		return nil, err
	}

	// Check if the verification token hasn't expired yet.
	if usr.UpdateKeyVerificationToken != nil {
		if usr.UpdateKeyVerificationExpiry > time.Now().Unix() {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusVerificationTokenUnexpired,
				ErrorContext: []string{
					strconv.FormatInt(usr.UpdateKeyVerificationExpiry, 10),
				},
			}
		}
	}

	// Generate a new verification token and expiry.
	token, expiry, err = p.generateVerificationTokenAndExpiry()
	if err != nil {
		return nil, err
	}

	// Add the updated user information to the db.
	usr.UpdateKeyVerificationToken = token
	usr.UpdateKeyVerificationExpiry = expiry

	identity := user.Identity{}
	copy(identity.Key[:], pk)
	usr.Identities = append(usr.Identities, identity)

	err = p.db.UserUpdate(*usr)
	if err != nil {
		return nil, err
	}

	if !p.test {
		// This is conditional on the email server being setup.
		err := p.emailUpdateUserKeyVerificationLink(usr.Email, u.PublicKey,
			hex.EncodeToString(token))
		if err != nil {
			return nil, err
		}
	}

	// Only set the token if email verification is disabled.
	if p.smtp.disabled {
		reply.VerificationToken = hex.EncodeToString(token)
	}
	return &reply, nil
}

// ProcessVerifyUpdateUserKey verifies the token generated for the recently
// generated key pair. It ensures that the token matches with the input and
// that the token hasn't expired.
func (p *politeiawww) ProcessVerifyUpdateUserKey(u *user.User, vu www.VerifyUpdateUserKey) (*user.User, error) {
	// Decode the verification token.
	token, err := hex.DecodeString(vu.VerificationToken)
	if err != nil {
		log.Debugf("VerifyUpdateUserKey failure for %v: verification token "+
			"could not be decoded: %v", u.Email, err)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenInvalid,
		}
	}

	// Check that the verification token matches.
	if !bytes.Equal(token, u.UpdateKeyVerificationToken) {
		log.Debugf("VerifyUpdateUserKey failure for %v: verification token "+
			"doesn't match, expected %v", u.Email,
			u.UpdateKeyVerificationToken, token)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenInvalid,
		}
	}

	// Check that the token hasn't expired.
	if u.UpdateKeyVerificationExpiry < time.Now().Unix() {
		log.Debugf("VerifyUpdateUserKey failure for %v: verification token "+
			"not expired yet", u.Email)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenExpired,
		}
	}

	// Check signature
	sig, err := util.ConvertSignature(vu.Signature)
	if err != nil {
		log.Debugf("VerifyUpdateUserKey failure for %v: signature could not "+
			"be decoded: %v", u.Email, err)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}

	id := u.Identities[len(u.Identities)-1]
	pi, err := identity.PublicIdentityFromBytes(id.Key[:])
	if err != nil {
		return nil, err
	}

	if !pi.VerifyMessage([]byte(vu.VerificationToken), sig) {
		log.Debugf("VerifyUpdateUserKey failure for %v: signature did not "+
			"match (pubkey: %v)", u.Email, pi.String())
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}

	// Associate the user id with the new public key.
	p.setUserPubkeyAssociaton(u, pi.String())

	// Clear out the verification token fields in the db and activate
	// the key and deactivate the one it's replacing.
	u.UpdateKeyVerificationToken = nil
	u.UpdateKeyVerificationExpiry = 0

	t := time.Now().Unix()
	for k, v := range u.Identities {
		if v.Deactivated == 0 {
			u.Identities[k].Deactivated = t
			break
		}
	}
	u.Identities[len(u.Identities)-1].Activated = t
	u.Identities[len(u.Identities)-1].Deactivated = 0

	return u, p.db.UserUpdate(*u)
}

// ProcessLogin checks that a user exists, is verified, and has
// the correct password.
func (p *politeiawww) ProcessLogin(l www.Login) (*www.LoginReply, error) {
	var (
		r       loginReplyWithError
		login   = make(chan loginReplyWithError)
		timeout = make(chan bool)
	)

	go func() {
		login <- p.login(&l)
	}()
	go func() {
		time.Sleep(MinimumLoginWaitTime)
		timeout <- true
	}()

	// Execute both goroutines in parallel, and only return
	// when both are finished.
	select {
	case r = <-login:
	case <-timeout:
	}

	select {
	case r = <-login:
	case <-timeout:
	}

	return r.reply, r.err
}

// ProcessChangeUsername checks that the password matches the one
// in the database, then checks that the username is valid and not
// already taken, then changes the user record in the database to
// the new username.
func (p *politeiawww) ProcessChangeUsername(email string, cu www.ChangeUsername) (*www.ChangeUsernameReply, error) {
	var reply www.ChangeUsernameReply

	// Get user from db.
	u, err := p.db.UserGet(email)
	if err != nil {
		return nil, err
	}

	// Check the user's password.
	err = bcrypt.CompareHashAndPassword(u.HashedPassword,
		[]byte(cu.Password))
	if err != nil {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidEmailOrPassword,
		}
	}

	// Format and validate the new username.
	newUsername := formatUsername(cu.NewUsername)
	err = validateUsername(newUsername)
	if err != nil {
		return nil, err
	}

	// Check for duplicate username
	_, err = p.db.UserGetByUsername(newUsername)
	switch err {
	case nil:
		// Duplicate
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusDuplicateUsername,
		}
	case user.ErrUserNotFound:
		// Doesn't exist, update username.
	default:
		// All other errors
		return nil, err
	}

	// Add the updated user information to the db.
	u.Username = newUsername
	err = p.db.UserUpdate(*u)
	if err != nil {
		return nil, err
	}

	return &reply, nil
}

// ProcessChangePassword checks that the current password matches the one
// in the database, then changes it to the new password.
func (p *politeiawww) ProcessChangePassword(email string, cp www.ChangePassword) (*www.ChangePasswordReply, error) {
	var reply www.ChangePasswordReply

	// Get user from db.
	u, err := p.db.UserGet(email)
	if err != nil {
		return nil, err
	}

	// Check the user's password.
	err = bcrypt.CompareHashAndPassword(u.HashedPassword,
		[]byte(cp.CurrentPassword))
	if err != nil {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidEmailOrPassword,
		}
	}

	// Validate the new password.
	err = validatePassword(cp.NewPassword)
	if err != nil {
		return nil, err
	}

	// Hash the user's password.
	hashedPassword, err := p.hashPassword(cp.NewPassword)
	if err != nil {
		return nil, err
	}

	// Add the updated user information to the db.
	u.HashedPassword = hashedPassword
	err = p.db.UserUpdate(*u)
	if err != nil {
		return nil, err
	}

	err = p.emailUserPasswordChanged(email)
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
func (p *politeiawww) ProcessResetPassword(rp www.ResetPassword) (*www.ResetPasswordReply, error) {
	var reply www.ResetPasswordReply

	// Get user from db.
	u, err := p.db.UserGet(rp.Email)
	if err != nil {
		if err == user.ErrInvalidEmail {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusMalformedEmail,
			}
		} else if err == user.ErrUserNotFound {
			log.Debugf("ResetPassword failure for %v: user not found", rp.Email)
			return &reply, nil
		}

		return nil, err
	}

	if rp.VerificationToken == "" {
		err = p.emailResetPassword(u, rp, &reply)
	} else {
		err = p.verifyResetPassword(u, rp, &reply)
	}

	if err != nil {
		return nil, err
	}

	return &reply, nil
}

// ProcessUserProposalCredits returns a list of the user's unspent proposal
// credits and a list of the user's spent proposal credits.
func ProcessUserProposalCredits(u *user.User) (*www.UserProposalCreditsReply, error) {
	// Convert from database proposal credits to www proposal credits.
	upc := make([]www.ProposalCredit, len(u.UnspentProposalCredits))
	for i, credit := range u.UnspentProposalCredits {
		upc[i] = convertWWWPropCreditFromDatabasePropCredit(credit)
	}
	spc := make([]www.ProposalCredit, len(u.SpentProposalCredits))
	for i, credit := range u.SpentProposalCredits {
		spc[i] = convertWWWPropCreditFromDatabasePropCredit(credit)
	}

	return &www.UserProposalCreditsReply{
		UnspentCredits: upc,
		SpentCredits:   spc,
	}, nil
}

// ProcessUserProposals returns a page of proposals for the given user.
func (p *politeiawww) ProcessUserProposals(up *www.UserProposals, isCurrentUser, isAdminUser bool) (*www.UserProposalsReply, error) {
	// Verify user exists
	_, err := p.getUserByIDStr(up.UserId)
	if err != nil {
		return nil, err
	}

	// Get a page of user proposals
	props, ps, err := p.getUserProps(proposalsFilter{
		After:  up.After,
		Before: up.Before,
		UserID: up.UserId,
		StateMap: map[www.PropStateT]bool{
			www.PropStateUnvetted: isCurrentUser || isAdminUser,
			www.PropStateVetted:   true,
		},
	})
	if err != nil {
		return nil, err
	}

	// Find the number of proposals the user has submitted. This
	// number will be different depending on who is requesting it.
	// Non-public proposals are included in the calculation when
	// an admin or the author is requesting the data.
	numProposals := ps.Public + ps.Abandoned
	if isCurrentUser || isAdminUser {
		numProposals += ps.NotReviewed + ps.UnreviewedChanges + ps.Censored
	}

	return &www.UserProposalsReply{
		Proposals:      props,
		NumOfProposals: numProposals,
	}, nil
}

func (p *politeiawww) ProcessCastVotes(ballot *www.Ballot) (*www.BallotReply, error) {
	log.Tracef("ProcessCastVotes")

	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	payload, err := decredplugin.EncodeBallot(convertBallotFromWWW(*ballot))
	if err != nil {
		return nil, err
	}
	pc := pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        decredplugin.ID,
		Command:   decredplugin.CmdBallot,
		CommandID: decredplugin.CmdBallot,
		Payload:   string(payload),
	}

	responseBody, err := p.makeRequest(http.MethodPost,
		pd.PluginCommandRoute, pc)
	if err != nil {
		return nil, err
	}

	var reply pd.PluginCommandReply
	err = json.Unmarshal(responseBody, &reply)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal "+
			"PluginCommandReply: %v", err)
	}

	// Verify the challenge.
	err = util.VerifyChallenge(p.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return nil, err
	}

	// Decode plugin reply
	br, err := decredplugin.DecodeBallotReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}
	brr := convertBallotReplyFromDecredPlugin(*br)
	return &brr, nil
}

// ProcessAuthorizeVote sends the authorizevote command to decred plugin to
// indicate that a proposal has been finalized and is ready to be voted on.
func (p *politeiawww) ProcessAuthorizeVote(av www.AuthorizeVote, u *user.User) (*www.AuthorizeVoteReply, error) {
	log.Tracef("ProcessAuthorizeVote %v", av.Token)

	// Get proposal from the cache
	pr, err := p.getProp(av.Token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusProposalNotFound,
			}
		}
		return nil, err
	}

	// Verify signature authenticity
	err = checkPublicKeyAndSignature(u, av.PublicKey, av.Signature,
		av.Token, pr.Version, av.Action)
	if err != nil {
		return nil, err
	}

	// Get vote details from cache
	vdr, err := p.decredVoteDetails(av.Token)
	if err != nil {
		return nil, fmt.Errorf("decredVoteDetails: %v", err)
	}
	vd := convertVoteDetailsReplyFromDecred(*vdr)

	// Verify record is in the right state and that the authorize
	// vote request is valid. A vote authorization may already
	// exist. We also allow vote authorizations to be revoked.
	switch {
	case pr.Status != www.PropStatusPublic:
		// Record not public
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusWrongStatus,
		}
	case vd.StartVoteReply.StartBlockHeight != "":
		// Vote has already started
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusWrongVoteStatus,
		}
	case av.Action != www.AuthVoteActionAuthorize &&
		av.Action != www.AuthVoteActionRevoke:
		// Invalid authorize vote action
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidAuthVoteAction,
		}
	case av.Action == www.AuthVoteActionAuthorize &&
		voteIsAuthorized(vd.AuthorizeVoteReply):
		// Cannot authorize vote; vote has already been
		// authorized
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVoteAlreadyAuthorized,
		}
	case av.Action == www.AuthVoteActionRevoke &&
		!voteIsAuthorized(vd.AuthorizeVoteReply):
		// Cannot revoke authorization; vote has not been
		// authorized
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVoteNotAuthorized,
		}
	case pr.PublicKey != av.PublicKey:
		// User is not the author. First make sure the author didn't
		// submit the proposal using an old identity.
		p.RLock()
		userID, ok := p.userPubkeys[pr.PublicKey]
		p.RUnlock()
		if ok {
			if u.ID.String() != userID {
				return nil, www.UserError{
					ErrorCode: www.ErrorStatusUserNotAuthor,
				}
			}
		} else {
			// This should not happen
			return nil, fmt.Errorf("proposal author not found")
		}
	}

	// Setup plugin command
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, fmt.Errorf("Random: %v", err)
	}

	dav := convertAuthorizeVoteFromWWW(av)
	payload, err := decredplugin.EncodeAuthorizeVote(dav)
	if err != nil {
		return nil, fmt.Errorf("EncodeAuthorizeVote: %v", err)
	}

	pc := pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        decredplugin.ID,
		Command:   decredplugin.CmdAuthorizeVote,
		CommandID: decredplugin.CmdAuthorizeVote + " " + av.Token,
		Payload:   string(payload),
	}

	// Send authorizevote plugin request
	responseBody, err := p.makeRequest(http.MethodPost,
		pd.PluginCommandRoute, pc)
	if err != nil {
		return nil, err
	}

	var reply pd.PluginCommandReply
	err = json.Unmarshal(responseBody, &reply)
	if err != nil {
		return nil, fmt.Errorf("Unmarshal PluginCommandReply: %v", err)
	}

	// Verify challenge
	err = util.VerifyChallenge(p.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return nil, fmt.Errorf("VerifyChallenge: %v", err)
	}

	// Decode plugin reply
	avr, err := decredplugin.DecodeAuthorizeVoteReply([]byte(reply.Payload))
	if err != nil {
		return nil, fmt.Errorf("DecodeAuthorizeVoteReply: %v", err)
	}

	if !p.test && avr.Action == www.AuthVoteActionAuthorize {
		p.fireEvent(EventTypeProposalVoteAuthorized,
			EventDataProposalVoteAuthorized{
				AuthorizeVote: &av,
				User:          u,
			},
		)
	}

	return &www.AuthorizeVoteReply{
		Action:  avr.Action,
		Receipt: avr.Receipt,
	}, nil
}

func validateVoteBit(vote www.Vote, bit uint64) error {
	if len(vote.Options) == 0 {
		return fmt.Errorf("vote corrupt")
	}
	if bit == 0 {
		return fmt.Errorf("invalid bit 0x%x", bit)
	}
	if vote.Mask&bit != bit {
		return fmt.Errorf("invalid mask 0x%x bit 0x%x",
			vote.Mask, bit)
	}

	for _, v := range vote.Options {
		if v.Bits == bit {
			return nil
		}
	}

	return fmt.Errorf("bit not found 0x%x", bit)
}

func (p *politeiawww) ProcessStartVote(sv www.StartVote, u *user.User) (*www.StartVoteReply, error) {
	log.Tracef("ProcessStartVote %v", sv.Vote.Token)

	// Verify user
	err := checkPublicKeyAndSignature(u, sv.PublicKey, sv.Signature,
		sv.Vote.Token)
	if err != nil {
		return nil, err
	}

	// Validate vote bits
	for _, v := range sv.Vote.Options {
		err = validateVoteBit(sv.Vote, v.Bits)
		if err != nil {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusInvalidPropVoteBits,
			}
		}
	}

	// Validate vote parameters
	if sv.Vote.Duration < p.cfg.VoteDurationMin ||
		sv.Vote.Duration > p.cfg.VoteDurationMax ||
		sv.Vote.QuorumPercentage > 100 || sv.Vote.PassPercentage > 100 {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidPropVoteParams,
		}
	}

	// Create vote bits as plugin payload
	dsv := convertStartVoteFromWWW(sv)
	payload, err := decredplugin.EncodeStartVote(dsv)
	if err != nil {
		return nil, err
	}

	// Get proposal from the cache
	pr, err := p.getProp(sv.Vote.Token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusProposalNotFound,
			}
		}
		return nil, err
	}

	// Get vote details from cache
	vdr, err := p.decredVoteDetails(sv.Vote.Token)
	if err != nil {
		return nil, fmt.Errorf("decredVoteDetails: %v", err)
	}
	vd := convertVoteDetailsReplyFromDecred(*vdr)

	// Ensure record is public, vote has been authorized,
	// and vote has not already started.
	if pr.Status != www.PropStatusPublic {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusWrongStatus,
		}
	}
	if !voteIsAuthorized(vd.AuthorizeVoteReply) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVoteNotAuthorized,
		}
	}
	if vd.StartVoteReply.StartBlockHeight != "" {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusWrongVoteStatus,
		}
	}

	// Tell decred plugin to start voting
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	pc := pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        decredplugin.ID,
		Command:   decredplugin.CmdStartVote,
		CommandID: decredplugin.CmdStartVote + " " + sv.Vote.Token,
		Payload:   string(payload),
	}

	responseBody, err := p.makeRequest(http.MethodPost,
		pd.PluginCommandRoute, pc)
	if err != nil {
		return nil, err
	}

	var reply pd.PluginCommandReply
	err = json.Unmarshal(responseBody, &reply)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal "+
			"PluginCommandReply: %v", err)
	}

	// Verify the challenge.
	err = util.VerifyChallenge(p.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return nil, err
	}

	vr, err := decredplugin.DecodeStartVoteReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}

	if !p.test {
		p.eventManager._fireEvent(EventTypeProposalVoteStarted,
			EventDataProposalVoteStarted{
				AdminUser: u,
				StartVote: &sv,
			},
		)
	}

	// return a copy
	rv := convertStartVoteReplyFromDecred(*vr)
	return &rv, nil
}

// ProcessPolicy returns the details of Politeia's restrictions on file uploads.
func ProcessPolicy() *www.PolicyReply {
	return &www.PolicyReply{
		MinPasswordLength:          www.PolicyMinPasswordLength,
		MinUsernameLength:          www.PolicyMinUsernameLength,
		MaxUsernameLength:          www.PolicyMaxUsernameLength,
		UsernameSupportedChars:     www.PolicyUsernameSupportedChars,
		ProposalListPageSize:       www.ProposalListPageSize,
		UserListPageSize:           www.UserListPageSize,
		MaxImages:                  www.PolicyMaxImages,
		MaxImageSize:               www.PolicyMaxImageSize,
		MaxMDs:                     www.PolicyMaxMDs,
		MaxMDSize:                  www.PolicyMaxMDSize,
		ValidMIMETypes:             mime.ValidMimeTypes(),
		MinProposalNameLength:      www.PolicyMinProposalNameLength,
		MaxProposalNameLength:      www.PolicyMaxProposalNameLength,
		ProposalNameSupportedChars: www.PolicyProposalNameSupportedChars,
		MaxCommentLength:           www.PolicyMaxCommentLength,
	}
}

func (p *politeiawww) getBestBlock() (uint64, error) {
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return 0, err
	}

	pc := pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        decredplugin.ID,
		Command:   decredplugin.CmdBestBlock,
		CommandID: decredplugin.CmdBestBlock,
		Payload:   "",
	}

	responseBody, err := p.makeRequest(http.MethodPost,
		pd.PluginCommandRoute, pc)
	if err != nil {
		return 0, err
	}

	var reply pd.PluginCommandReply
	err = json.Unmarshal(responseBody, &reply)
	if err != nil {
		return 0, fmt.Errorf("Could not unmarshal "+
			"PluginCommandReply: %v", err)
	}

	// Verify the challenge.
	err = util.VerifyChallenge(p.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return 0, err
	}

	bestBlock, err := strconv.ParseUint(reply.Payload, 10, 64)
	if err != nil {
		return 0, err
	}

	return bestBlock, nil
}

func (p *politeiawww) getPluginInventory() ([]Plugin, error) {
	log.Tracef("getPluginInventory")

	// Setup politeiad request
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	pi := pd.PluginInventory{
		Challenge: hex.EncodeToString(challenge),
	}

	// Send politeiad request
	responseBody, err := p.makeRequest(http.MethodPost,
		pd.PluginInventoryRoute, pi)
	if err != nil {
		return nil, fmt.Errorf("makeRequest: %v", err)
	}

	// Handle response
	var reply pd.PluginInventoryReply
	err = json.Unmarshal(responseBody, &reply)
	if err != nil {
		return nil, err
	}

	err = util.VerifyChallenge(p.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return nil, err
	}

	plugins := make([]Plugin, 0, len(reply.Plugins))
	for _, v := range reply.Plugins {
		plugins = append(plugins, convertPluginFromPD(v))
	}

	return plugins, nil
}

// voteIsAuthorized returns whether the author of the proposal has authorized
// an admin to start the voting period for the proposal.
func voteIsAuthorized(avr www.AuthorizeVoteReply) bool {
	if avr.Receipt == "" {
		// Vote has not been authorized yet
		return false
	} else if avr.Action == www.AuthVoteActionRevoke {
		// Vote authorization was revoked
		return false
	}
	return true
}

func getVoteStatus(avr www.AuthorizeVoteReply, svr www.StartVoteReply, bestBlock uint64) www.PropVoteStatusT {
	if svr.StartBlockHeight == "" {
		// Vote has not started. Check if it's been authorized yet.
		if voteIsAuthorized(avr) {
			return www.PropVoteStatusAuthorized
		} else {
			return www.PropVoteStatusNotAuthorized
		}
	}

	// Vote has at least been started. Check if it has finished.
	ee, err := strconv.ParseUint(svr.EndHeight, 10, 64)
	if err != nil {
		// This should not happen
		log.Errorf("getVoteStatus: ParseUint failed on '%v': %v",
			svr.EndHeight, err)
		return www.PropVoteStatusInvalid
	}

	if bestBlock >= ee {
		return www.PropVoteStatusFinished
	}
	return www.PropVoteStatusStarted
}

// getProposalName returns the proposal name based on the index markdown file.
func getProposalName(files []www.File) (string, error) {
	for _, file := range files {
		if file.Name == indexFile {
			return util.GetProposalName(file.Payload)
		}
	}
	return "", nil
}

// convertWWWPropCreditFromDatabasePropCredit coverts a database proposal
// credit to a v1 proposal credit.
func convertWWWPropCreditFromDatabasePropCredit(credit user.ProposalCredit) www.ProposalCredit {
	return www.ProposalCredit{
		PaywallID:     credit.PaywallID,
		Price:         credit.Price,
		DatePurchased: credit.DatePurchased,
		TxID:          credit.TxID,
	}
}
