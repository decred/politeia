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
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrtime/merkle"
	"github.com/decred/politeia/decredplugin"
	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/api/v1/mime"
	"github.com/decred/politeia/politeiad/cache"
	"github.com/decred/politeia/politeiad/cache/cockroachdb"
	www "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/database"
	"github.com/decred/politeia/politeiawww/database/localdb"
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

// politeiawww backend construct
type backend struct {
	sync.RWMutex

	db           database.Database // User database
	cache        cache.Cache       // Records cache
	cfg          *config
	params       *chaincfg.Params
	client       *http.Client // politeiad client
	eventManager *EventManager
	plugins      []Plugin

	// These properties are only used for testing.
	test                   bool
	verificationExpiryTime time.Duration

	// Following entries require locks
	userPubkeys     map[string]string               // [pubkey][userid]
	userPaywallPool map[uuid.UUID]paywallPoolMember // [userid][paywallPoolMember]
	commentScores   map[string]int64                // [token+commentID]resultVotes
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
func checkPublicKeyAndSignature(user *database.User, publicKey string, signature string, elements ...string) error {
	id, err := checkPublicKey(user, publicKey)
	if err != nil {
		return err
	}

	return checkSignature(id, signature, elements...)
}

// checkPublicKey compares the supplied public key against the one stored in
// the user database. It will return the active identity if there are no errors.
func checkPublicKey(user *database.User, pk string) ([]byte, error) {
	id, ok := database.ActiveIdentity(user.Identities)
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

func formatUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
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

func (b *backend) getVerificationExpiryTime() time.Duration {
	if b.verificationExpiryTime != time.Duration(0) {
		return b.verificationExpiryTime
	}
	return time.Duration(www.VerificationExpiryHours) * time.Hour
}

func (b *backend) generateVerificationTokenAndExpiry() ([]byte, int64, error) {
	token, err := util.Random(www.VerificationTokenSize)
	if err != nil {
		return nil, 0, err
	}

	expiry := time.Now().Add(b.getVerificationExpiryTime()).Unix()

	return token, expiry, nil
}

// checkUserIsLocked checks if a user is locked after many login attempts
func checkUserIsLocked(failedLoginAttempts uint64) bool {
	return failedLoginAttempts >= LoginAttemptsToLockUser
}

func (b *backend) getUserIDByPubKey(pubkey string) (string, bool) {
	b.RLock()
	defer b.RUnlock()

	userID, ok := b.userPubkeys[pubkey]
	return userID, ok
}

// hashPassword hashes the given password string with the default bcrypt cost
// or the minimum cost if the test flag is set to speed up running tests.
func (b *backend) hashPassword(password string) ([]byte, error) {
	if b.test {
		return bcrypt.GenerateFromPassword([]byte(password),
			bcrypt.MinCost)
	}
	return bcrypt.GenerateFromPassword([]byte(password),
		bcrypt.DefaultCost)
}

// getUsernameById returns the username given its id. If the id is invalid,
// it returns an empty string.
func (b *backend) getUsernameById(userIdStr string) string {
	userId, err := uuid.Parse(userIdStr)
	if err != nil {
		return ""
	}

	user, err := b.db.UserGetById(userId)
	if err != nil {
		return ""
	}

	return user.Username
}

func (b *backend) login(l *www.Login) loginReplyWithError {
	// Get user from db.
	user, err := b.db.UserGet(l.Email)
	if err != nil {
		if err == database.ErrUserNotFound {
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
	err = bcrypt.CompareHashAndPassword(user.HashedPassword,
		[]byte(l.Password))
	if err != nil {
		if !checkUserIsLocked(user.FailedLoginAttempts) {
			user.FailedLoginAttempts++
			err := b.db.UserUpdate(*user)
			if err != nil {
				return loginReplyWithError{
					reply: nil,
					err:   err,
				}
			}

			// Check if the user is locked again so we can send an
			// email.
			if checkUserIsLocked(user.FailedLoginAttempts) && !b.test {
				// This is conditional on the email server
				// being setup.
				err := b.emailUserLocked(user.Email)
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
	if user.NewUserVerificationToken != nil {
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
	if user.Deactivated {
		log.Debugf("Login failure for %v: user deactivated", l.Email)
		return loginReplyWithError{
			reply: nil,
			err: www.UserError{
				ErrorCode: www.ErrorStatusUserDeactivated,
			},
		}
	}

	// Check if user is locked due to too many login attempts
	if checkUserIsLocked(user.FailedLoginAttempts) {
		log.Debugf("Login failure for %v: user locked",
			l.Email)
		return loginReplyWithError{
			reply: nil,
			err: www.UserError{
				ErrorCode: www.ErrorStatusUserLocked,
			},
		}
	}

	lastLoginTime := user.LastLoginTime
	user.FailedLoginAttempts = 0
	user.LastLoginTime = time.Now().Unix()
	err = b.db.UserUpdate(*user)
	if err != nil {
		return loginReplyWithError{
			reply: nil,
			err:   err,
		}
	}
	reply, err := b.CreateLoginReply(user, lastLoginTime)
	return loginReplyWithError{
		reply: reply,
		err:   err,
	}
}

// initUserPubkeys initializes the userPubkeys map with all the pubkey-userid
// associations that are found in the database.
//
// This function must be called WITHOUT the lock held.
func (b *backend) initUserPubkeys() error {
	b.Lock()
	defer b.Unlock()

	return b.db.AllUsers(func(u *database.User) {
		userId := u.ID.String()
		for _, v := range u.Identities {
			key := hex.EncodeToString(v.Key[:])
			b.userPubkeys[key] = userId
		}
	})
}

// setUserPubkeyAssociaton associates a public key with a user id in
// the userPubkeys cache.
//
// This function must be called WITHOUT the lock held.
func (b *backend) setUserPubkeyAssociaton(user *database.User, publicKey string) {
	b.Lock()
	defer b.Unlock()

	userID := user.ID.String()
	b.userPubkeys[publicKey] = userID
}

// removeUserPubkeyAssociaton removes a public key from the
// userPubkeys cache.
//
// This function must be called WITHOUT the lock held.
func (b *backend) removeUserPubkeyAssociaton(user *database.User, publicKey string) {
	b.Lock()
	defer b.Unlock()

	delete(b.userPubkeys, publicKey)
}

// makeRequest makes an http request to the method and route provided,
// serializing the provided object as the request body.
func (b *backend) makeRequest(method string, route string, v interface{}) ([]byte, error) {
	var (
		requestBody []byte
		err         error
	)
	if v != nil {
		requestBody, err = json.Marshal(v)
		if err != nil {
			return nil, err
		}
	}

	fullRoute := b.cfg.RPCHost + route

	if b.client == nil {
		b.client, err = util.NewClient(false, b.cfg.RPCCert)
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequest(method, fullRoute,
		bytes.NewReader(requestBody))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(b.cfg.RPCUser, b.cfg.RPCPass)
	r, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		var pdErrorReply www.PDErrorReply
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&pdErrorReply); err != nil {
			return nil, err
		}

		return nil, www.PDError{
			HTTPCode:   r.StatusCode,
			ErrorReply: pdErrorReply,
		}
	}

	responseBody := util.ConvertBodyToByteArray(r.Body, false)
	return responseBody, nil
}

func (b *backend) initCommentScores() error {
	log.Tracef("initCommentScores")

	// Fetch decred plugin inventory from cache
	ir, err := b.decredInventory()
	if err != nil {
		return fmt.Errorf("decredInventory: %v", err)
	}

	// XXX this could be done much more efficiently since we
	// already have all of the like comments in the inventory
	// repsonse, but re-using the updateCommentScore function is
	// simplier. This only gets run on startup so I'm not that
	// worried about performance for right now.
	for _, v := range ir.Comments {
		_, err := b.updateCommentScore(v.Token, v.CommentID)
		if err != nil {
			return fmt.Errorf("updateCommentScore: %v", err)
		}
	}

	return nil
}

func (b *backend) validateUsername(username string, userToMatch *database.User) error {
	if len(username) < www.PolicyMinUsernameLength ||
		len(username) > www.PolicyMaxUsernameLength {
		log.Tracef("Username not within bounds: %s", username)
		return www.UserError{
			ErrorCode: www.ErrorStatusMalformedUsername,
		}
	}

	if !validUsername.MatchString(username) {
		log.Tracef("Username not valid: %s %s", username, validUsername.String())
		return www.UserError{
			ErrorCode: www.ErrorStatusMalformedUsername,
		}
	}

	user, err := b.db.UserGetByUsername(username)
	if err != nil {
		return err
	}
	if user != nil {
		if userToMatch == nil || user.ID != userToMatch.ID {
			return www.UserError{
				ErrorCode: www.ErrorStatusDuplicateUsername,
			}
		}
	}

	return nil
}

func (b *backend) validatePassword(password string) error {
	if len(password) < www.PolicyMinPasswordLength {
		return www.UserError{
			ErrorCode: www.ErrorStatusMalformedPassword,
		}
	}

	return nil
}

func (b *backend) validatePubkey(publicKey string) ([]byte, error) {
	pk, err := hex.DecodeString(publicKey)
	if err != nil {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidPublicKey,
		}
	}

	var emptyPK [identity.PublicKeySize]byte
	if len(pk) != len(emptyPK) ||
		bytes.Equal(pk, emptyPK[:]) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidPublicKey,
		}
	}

	return pk, nil
}

func (b *backend) validatePubkeyIsUnique(publicKey string, user *database.User) error {
	b.RLock()
	userIDStr, ok := b.userPubkeys[publicKey]
	b.RUnlock()
	if !ok {
		return nil
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return err
	}

	if user != nil && user.ID == userID {
		return nil
	}

	return www.UserError{
		ErrorCode: www.ErrorStatusDuplicatePublicKey,
	}
}

func (b *backend) validateProposal(np www.NewProposal, user *database.User) error {
	log.Tracef("validateProposal")

	// Obtain signature
	sig, err := util.ConvertSignature(np.Signature)
	if err != nil {
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}

	// Verify public key
	id, err := checkPublicKey(user, np.PublicKey)
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

	// proposal summary validation
	summary, err := getProposalSummary(np.Files)
	if err != nil {
		return err
	}
	if !util.IsValidProposalSummary(summary) {
		return www.UserError{
			ErrorCode:    www.ErrorStatusProposalInvalidSummary,
			ErrorContext: []string{util.CreateProposalSummaryRegex()},
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

func (b *backend) setNewUserVerificationAndIdentity(
	user *database.User,
	token []byte,
	expiry int64,
	includeResend bool,
	pk []byte,
) {
	user.NewUserVerificationToken = token
	user.NewUserVerificationExpiry = expiry
	if includeResend {
		// This field is used to support requesting another registration email
		// quickly, without having to wait the full email-spam-prevention
		// period.
		user.ResendNewUserVerificationExpiry = expiry
	}
	user.Identities = []database.Identity{{
		Activated: time.Now().Unix(),
	}}
	copy(user.Identities[0].Key[:], pk)
}

func (b *backend) emailResetPassword(user *database.User, rp www.ResetPassword, rpr *www.ResetPasswordReply) error {
	if user.ResetPasswordVerificationToken != nil {
		if user.ResetPasswordVerificationExpiry > time.Now().Unix() {
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
		log.Debugf("VerifyResetPassword failure for %v: verification token "+
			"could not be decoded: %v", rp.Email, err)
		return www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenInvalid,
		}
	}

	// Check that the verification token matches.
	if !bytes.Equal(token, user.ResetPasswordVerificationToken) {
		log.Debugf("VerifyResetPassword failure for %v: verification token doesn't "+
			"match, expected %v", rp.Email,
			user.ResetPasswordVerificationToken)
		return www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenInvalid,
		}
	}

	// Check that the token hasn't expired.
	if user.ResetPasswordVerificationExpiry < time.Now().Unix() {
		log.Debugf("VerifyResetPassword failure for %v: verification token "+
			"not expired yet", rp.Email)
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

	// Clear out the verification token fields, set the new password in the db,
	// and unlock account
	user.ResetPasswordVerificationToken = nil
	user.ResetPasswordVerificationExpiry = 0
	user.HashedPassword = hashedPassword
	user.FailedLoginAttempts = 0

	return b.db.UserUpdate(*user)
}

func (b *backend) CreateLoginReply(user *database.User, lastLoginTime int64) (*www.LoginReply, error) {
	activeIdentity, ok := database.ActiveIdentityString(user.Identities)
	if !ok {
		activeIdentity = ""
	}

	reply := www.LoginReply{
		IsAdmin:         user.Admin,
		UserID:          user.ID.String(),
		Email:           user.Email,
		Username:        user.Username,
		PublicKey:       activeIdentity,
		PaywallTxID:     user.NewUserPaywallTx,
		ProposalCredits: ProposalCreditBalance(user),
		LastLoginTime:   lastLoginTime,
	}

	if !b.HasUserPaid(user) {
		err := b.GenerateNewUserPaywall(user)
		if err != nil {
			return nil, err
		}

		reply.PaywallAddress = user.NewUserPaywallAddress
		reply.PaywallAmount = user.NewUserPaywallAmount
		reply.PaywallTxNotBefore = user.NewUserPaywallTxNotBefore
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
func (b *backend) ProcessNewUser(u www.NewUser) (*www.NewUserReply, error) {
	var (
		reply  www.NewUserReply
		token  []byte
		expiry int64
	)

	existingUser, err := b.db.UserGet(u.Email)
	if err == nil {
		// Check if the user is already verified.
		if existingUser.NewUserVerificationToken == nil {
			return &reply, nil
		}

		// Check if the verification token hasn't expired yet.
		if existingUser.NewUserVerificationExpiry > time.Now().Unix() {
			return &reply, nil
		}
	}

	// Ensure we got a proper pubkey.
	pk, err := b.validatePubkey(u.PublicKey)
	if err != nil {
		return nil, err
	}

	// Format and validate the username.
	username := formatUsername(u.Username)
	err = b.validateUsername(username, existingUser)
	if err != nil {
		return nil, err
	}

	// Validate the password.
	err = b.validatePassword(u.Password)
	if err != nil {
		return nil, err
	}

	// Validate that the pubkey isn't already taken.
	err = b.validatePubkeyIsUnique(u.PublicKey, existingUser)
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

	// Create a new database user with the provided information.
	newUser := database.User{
		Email:          strings.ToLower(u.Email),
		Username:       username,
		HashedPassword: hashedPassword,
		Admin:          false,
	}
	b.setNewUserVerificationAndIdentity(&newUser, token, expiry, false, pk)

	if !b.test {
		// Try to email the verification link first; if it fails, then
		// the new user won't be created.
		//
		// This is conditional on the email server being setup.
		err := b.emailNewUserVerificationLink(u.Email, hex.EncodeToString(token), u.Username)
		if err != nil {
			log.Errorf("Email new user verification link failed %v, %v", u.Email, err)
			return &reply, nil
		}
	}

	// Check if the user already exists.
	if existingUser != nil {
		existingPublicKey := hex.EncodeToString(existingUser.Identities[0].Key[:])
		b.removeUserPubkeyAssociaton(existingUser, existingPublicKey)

		// Update the user in the db.
		newUser.ID = existingUser.ID
		err = b.db.UserUpdate(newUser)
	} else {
		// Save the new user in the db.
		err = b.db.UserNew(newUser)
	}

	// Error handling for the db write.
	if err != nil {
		if err == database.ErrInvalidEmail {
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
	existingUser, err = b.db.UserGet(newUser.Email)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve account info for %v: %v",
			newUser.Email, err)
	}

	// Associate the user id with the new public key.
	b.setUserPubkeyAssociaton(existingUser, u.PublicKey)

	// Derive paywall information for this user if the paywall is enabled.
	err = b.GenerateNewUserPaywall(existingUser)
	if err != nil {
		return nil, err
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
			log.Debugf("VerifyNewUser failure for %v: user not found",
				u.Email)
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusVerificationTokenInvalid,
			}
		}
		return nil, err
	}

	// Decode the verification token.
	token, err := hex.DecodeString(u.VerificationToken)
	if err != nil {
		log.Debugf("VerifyNewUser failure for %v: verification token could "+
			"not be decoded: %v", u.Email, err)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenInvalid,
		}
	}

	// Check that the verification token matches.
	if !bytes.Equal(token, user.NewUserVerificationToken) {
		log.Debugf("VerifyNewUser failure for %v: verification token doesn't "+
			"match, expected %v", u.Email, user.NewUserVerificationToken)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenInvalid,
		}
	}

	// Check that the token hasn't expired.
	if time.Now().Unix() > user.NewUserVerificationExpiry {
		log.Debugf("VerifyNewUser failure for %v: verification token expired",
			u.Email)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenExpired,
		}
	}

	// Check signature
	sig, err := util.ConvertSignature(u.Signature)
	if err != nil {
		log.Debugf("VerifyNewUser failure for %v: signature could not be "+
			"decoded: %v", u.Email, err)
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
		log.Debugf("VerifyNewUser failure for %v: no public key",
			u.Email)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusNoPublicKey,
		}
	}
	if !pi.VerifyMessage([]byte(u.VerificationToken), sig) {
		log.Debugf("VerifyNewUser failure for %v: signature doesn't match "+
			"(pubkey: %v)", u.Email, pi.String())
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}

	// Clear out the verification token fields in the db.
	user.NewUserVerificationToken = nil
	user.NewUserVerificationExpiry = 0
	user.ResendNewUserVerificationExpiry = 0
	err = b.db.UserUpdate(*user)
	if err != nil {
		return nil, err
	}

	b.addUserToPaywallPoolLock(user, paywallTypeUser)

	return user, nil
}

// ProcessResendVerification resends a new user verification email if the
// user exists and his verification token is expired.
func (b *backend) ProcessResendVerification(rv *www.ResendVerification) (*www.ResendVerificationReply, error) {
	rvr := www.ResendVerificationReply{}

	// Get user from db.
	user, err := b.db.UserGet(rv.Email)
	if err != nil {
		if err == database.ErrUserNotFound {
			log.Debugf("ResendVerification failure for %v: user not found",
				rv.Email)
			return &rvr, nil
		}
		return nil, err
	}

	// Don't do anything if the user is already verified or the token hasn't
	// expired yet.
	if user.NewUserVerificationToken == nil {
		log.Debugf("ResendVerification failure for %v: user already verified",
			rv.Email)
		return &rvr, nil
	}

	if user.ResendNewUserVerificationExpiry > time.Now().Unix() {
		log.Debugf("ResendVerification failure for %v: verification token "+
			"not expired yet", rv.Email)
		return &rvr, nil
	}

	// Ensure we got a proper pubkey.
	pk, err := b.validatePubkey(rv.PublicKey)
	if err != nil {
		return nil, err
	}

	// Validate that the pubkey isn't already taken.
	err = b.validatePubkeyIsUnique(rv.PublicKey, user)
	if err != nil {
		return nil, err
	}

	// Generate the verification token and expiry.
	token, expiry, err := b.generateVerificationTokenAndExpiry()
	if err != nil {
		return nil, err
	}

	// Remove the original pubkey from the cache.
	existingPublicKey := hex.EncodeToString(user.Identities[0].Key[:])
	b.removeUserPubkeyAssociaton(user, existingPublicKey)

	// Set a new verificaton token and identity.
	b.setNewUserVerificationAndIdentity(user, token, expiry, true, pk)

	// Associate the user id with the new identity.
	b.setUserPubkeyAssociaton(user, rv.PublicKey)

	// Update the user in the db.
	err = b.db.UserUpdate(*user)
	if err != nil {
		return nil, err
	}

	if !b.test {
		// This is conditional on the email server being setup.
		err := b.emailNewUserVerificationLink(user.Email, hex.EncodeToString(token), user.Username)
		if err != nil {
			return nil, err
		}
	}

	// Only set the token if email verification is disabled.
	if b.cfg.SMTP == nil {
		rvr.VerificationToken = hex.EncodeToString(token)
	}
	return &rvr, nil
}

// ProcessUpdateUserKey sets a verification token and expiry to allow the user to
// update his key pair; the token must be verified before it expires. If the
// token is already set and is expired, it generates a new one.
func (b *backend) ProcessUpdateUserKey(user *database.User, u www.UpdateUserKey) (*www.UpdateUserKeyReply, error) {
	var reply www.UpdateUserKeyReply
	var token []byte
	var expiry int64

	// Ensure we got a proper pubkey.
	pk, err := b.validatePubkey(u.PublicKey)
	if err != nil {
		return nil, err
	}

	// Validate that the pubkey isn't already taken.
	err = b.validatePubkeyIsUnique(u.PublicKey, nil)
	if err != nil {
		return nil, err
	}

	// Check if the verification token hasn't expired yet.
	if user.UpdateKeyVerificationToken != nil {
		if user.UpdateKeyVerificationExpiry > time.Now().Unix() {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusVerificationTokenUnexpired,
				ErrorContext: []string{
					strconv.FormatInt(user.UpdateKeyVerificationExpiry, 10),
				},
			}
		}
	}

	// Generate a new verification token and expiry.
	token, expiry, err = b.generateVerificationTokenAndExpiry()
	if err != nil {
		return nil, err
	}

	// Add the updated user information to the db.
	user.UpdateKeyVerificationToken = token
	user.UpdateKeyVerificationExpiry = expiry

	identity := database.Identity{}
	copy(identity.Key[:], pk)
	user.Identities = append(user.Identities, identity)

	err = b.db.UserUpdate(*user)
	if err != nil {
		return nil, err
	}

	if !b.test {
		// This is conditional on the email server being setup.
		err := b.emailUpdateUserKeyVerificationLink(user.Email, u.PublicKey,
			hex.EncodeToString(token))
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

// ProcessVerifyUpdateUserKey verifies the token generated for the recently
// generated key pair. It ensures that the token matches with the input and
// that the token hasn't expired.
func (b *backend) ProcessVerifyUpdateUserKey(user *database.User, vu www.VerifyUpdateUserKey) (*database.User, error) {
	// Decode the verification token.
	token, err := hex.DecodeString(vu.VerificationToken)
	if err != nil {
		log.Debugf("VerifyUpdateUserKey failure for %v: verification token "+
			"could not be decoded: %v", user.Email, err)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenInvalid,
		}
	}

	// Check that the verification token matches.
	if !bytes.Equal(token, user.UpdateKeyVerificationToken) {
		log.Debugf("VerifyUpdateUserKey failure for %v: verification token "+
			"doesn't match, expected %v", user.Email,
			user.UpdateKeyVerificationToken, token)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenInvalid,
		}
	}

	// Check that the token hasn't expired.
	if user.UpdateKeyVerificationExpiry < time.Now().Unix() {
		log.Debugf("VerifyUpdateUserKey failure for %v: verification token "+
			"not expired yet", user.Email)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenExpired,
		}
	}

	// Check signature
	sig, err := util.ConvertSignature(vu.Signature)
	if err != nil {
		log.Debugf("VerifyUpdateUserKey failure for %v: signature could not "+
			"be decoded: %v", user.Email, err)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}

	id := user.Identities[len(user.Identities)-1]
	pi, err := identity.PublicIdentityFromBytes(id.Key[:])
	if err != nil {
		return nil, err
	}

	if !pi.VerifyMessage([]byte(vu.VerificationToken), sig) {
		log.Debugf("VerifyUpdateUserKey failure for %v: signature did not "+
			"match (pubkey: %v)", user.Email, pi.String())
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}

	// Associate the user id with the new public key.
	b.setUserPubkeyAssociaton(user, pi.String())

	// Clear out the verification token fields in the db and activate
	// the key and deactivate the one it's replacing.
	user.UpdateKeyVerificationToken = nil
	user.UpdateKeyVerificationExpiry = 0

	t := time.Now().Unix()
	for k, v := range user.Identities {
		if v.Deactivated == 0 {
			user.Identities[k].Deactivated = t
			break
		}
	}
	user.Identities[len(user.Identities)-1].Activated = t
	user.Identities[len(user.Identities)-1].Deactivated = 0

	return user, b.db.UserUpdate(*user)
}

// ProcessLogin checks that a user exists, is verified, and has
// the correct password.
func (b *backend) ProcessLogin(l www.Login) (*www.LoginReply, error) {
	var (
		r       loginReplyWithError
		login   = make(chan loginReplyWithError)
		timeout = make(chan bool)
	)

	go func() {
		login <- b.login(&l)
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
func (b *backend) ProcessChangeUsername(email string, cu www.ChangeUsername) (*www.ChangeUsernameReply, error) {
	var reply www.ChangeUsernameReply

	// Get user from db.
	user, err := b.db.UserGet(email)
	if err != nil {
		return nil, err
	}

	// Check the user's password.
	err = bcrypt.CompareHashAndPassword(user.HashedPassword,
		[]byte(cu.Password))
	if err != nil {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidEmailOrPassword,
		}
	}

	// Format and validate the new username.
	newUsername := formatUsername(cu.NewUsername)
	err = b.validateUsername(newUsername, nil)
	if err != nil {
		return nil, err
	}

	// Add the updated user information to the db.
	user.Username = newUsername
	err = b.db.UserUpdate(*user)
	if err != nil {
		return nil, err
	}

	return &reply, nil
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

	err = b.emailUserPasswordChanged(email)
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
			log.Debugf("ResetPassword failure for %v: user not found", rp.Email)
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

// ProcessUserProposalCredits returns a list of the user's unspent proposal
// credits and a list of the user's spent proposal credits.
func (b *backend) ProcessUserProposalCredits(user *database.User) (*www.UserProposalCreditsReply, error) {
	// Convert from database proposal credits to www proposal credits.
	upc := make([]www.ProposalCredit, len(user.UnspentProposalCredits))
	for i, credit := range user.UnspentProposalCredits {
		upc[i] = convertWWWPropCreditFromDatabasePropCredit(credit)
	}
	spc := make([]www.ProposalCredit, len(user.SpentProposalCredits))
	for i, credit := range user.SpentProposalCredits {
		spc[i] = convertWWWPropCreditFromDatabasePropCredit(credit)
	}

	return &www.UserProposalCreditsReply{
		UnspentCredits: upc,
		SpentCredits:   spc,
	}, nil
}

// ProcessUserProposals returns a page of proposals for the given user.
func (b *backend) ProcessUserProposals(up *www.UserProposals, isCurrentUser, isAdminUser bool) (*www.UserProposalsReply, error) {
	// Verify user exists
	_, err := b.getUserByIDStr(up.UserId)
	if err != nil {
		return nil, err
	}

	// Get a page of user proposals
	props, ps, err := b.getUserProps(proposalsFilter{
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

func (b *backend) ProcessCastVotes(ballot *www.Ballot) (*www.BallotReply, error) {
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

	responseBody, err := b.makeRequest(http.MethodPost,
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
	err = util.VerifyChallenge(b.cfg.Identity, challenge, reply.Response)
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
func (b *backend) ProcessAuthorizeVote(av www.AuthorizeVote, user *database.User) (*www.AuthorizeVoteReply, error) {
	log.Tracef("ProcessAuthorizeVote %v", av.Token)

	// Get proposal from the cache
	pr, err := b.getProp(av.Token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusProposalNotFound,
			}
		}
		return nil, err
	}

	// Verify signature authenticity
	err = checkPublicKeyAndSignature(user, av.PublicKey, av.Signature,
		av.Token, pr.Version, av.Action)
	if err != nil {
		return nil, err
	}

	// Get vote details from cache
	vdr, err := b.decredVoteDetails(av.Token)
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
		b.RLock()
		userID, ok := b.userPubkeys[pr.PublicKey]
		b.RUnlock()
		if ok {
			if user.ID.String() != userID {
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
	responseBody, err := b.makeRequest(http.MethodPost,
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
	err = util.VerifyChallenge(b.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return nil, fmt.Errorf("VerifyChallenge: %v", err)
	}

	// Decode plugin reply
	avr, err := decredplugin.DecodeAuthorizeVoteReply([]byte(reply.Payload))
	if err != nil {
		return nil, fmt.Errorf("DecodeAuthorizeVoteReply: %v", err)
	}

	if !b.test && avr.Action == www.AuthVoteActionAuthorize {
		b.fireEvent(EventTypeProposalVoteAuthorized,
			EventDataProposalVoteAuthorized{
				AuthorizeVote: &av,
				User:          user,
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

func (b *backend) ProcessStartVote(sv www.StartVote, user *database.User) (*www.StartVoteReply, error) {
	log.Tracef("ProcessStartVote %v", sv.Vote.Token)

	// Verify user
	err := checkPublicKeyAndSignature(user, sv.PublicKey, sv.Signature,
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
	if sv.Vote.Duration < b.cfg.VoteDurationMin ||
		sv.Vote.Duration > b.cfg.VoteDurationMax ||
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
	pr, err := b.getProp(sv.Vote.Token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusProposalNotFound,
			}
		}
		return nil, err
	}

	// Get vote details from cache
	vdr, err := b.decredVoteDetails(sv.Vote.Token)
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

	responseBody, err := b.makeRequest(http.MethodPost,
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
	err = util.VerifyChallenge(b.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return nil, err
	}

	vr, err := decredplugin.DecodeStartVoteReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}

	if !b.test {
		b.eventManager._fireEvent(EventTypeProposalVoteStarted,
			EventDataProposalVoteStarted{
				AdminUser: user,
				StartVote: &sv,
			},
		)
	}

	// return a copy
	rv := convertStartVoteReplyFromDecred(*vr)
	return &rv, nil
}

// ProcessPolicy returns the details of Politeia's restrictions on file uploads.
func (b *backend) ProcessPolicy(p www.Policy) *www.PolicyReply {
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
		MinProposalSummaryLength:   www.PolicyMinProposalSummaryLength,
		MaxProposalSummaryLength:   www.PolicyMaxProposalSummaryLength,
	}
}

func (b *backend) getBestBlock() (uint64, error) {
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

	responseBody, err := b.makeRequest(http.MethodPost,
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
	err = util.VerifyChallenge(b.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return 0, err
	}

	bestBlock, err := strconv.ParseUint(reply.Payload, 10, 64)
	if err != nil {
		return 0, err
	}

	return bestBlock, nil
}

func (b *backend) getPluginInventory() ([]Plugin, error) {
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
	responseBody, err := b.makeRequest(http.MethodPost,
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

	err = util.VerifyChallenge(b.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return nil, err
	}

	plugins := make([]Plugin, 0, len(reply.Plugins))
	for _, v := range reply.Plugins {
		plugins = append(plugins, convertPluginFromPD(v))
	}

	return plugins, nil
}

// NewBackend creates a new backend context for use in www and tests.
func NewBackend(cfg *config) (*backend, error) {
	// Setup database.
	// localdb.UseLogger(localdbLog)
	db, err := localdb.New(cfg.DataDir)
	if err != nil {
		return nil, err
	}

	// Setup cache connection
	cockroachdb.UseLogger(cockroachdbLog)
	net := filepath.Base(cfg.DataDir)
	cdb, err := cockroachdb.New(cockroachdb.UserPoliteiawww, cfg.CacheHost,
		net, cfg.CacheRootCert, cfg.CacheCert, cfg.CacheKey)
	if err != nil {
		if err == cache.ErrWrongVersion {
			err = fmt.Errorf("wrong cache version, restart politeiad " +
				"to rebuild the cache")
		}
		return nil, err
	}

	// Context
	b := &backend{
		db:              db,
		cache:           cdb,
		cfg:             cfg,
		userPubkeys:     make(map[string]string),
		userPaywallPool: make(map[uuid.UUID]paywallPoolMember),
		commentScores:   make(map[string]int64),
	}

	// Get plugins from politeiad
	p, err := b.getPluginInventory()
	if err != nil {
		return nil, fmt.Errorf("getPluginInventory: %v", err)
	}
	b.plugins = p

	// Register plugins with cache
	for _, v := range b.plugins {
		p := convertPluginToCache(v)
		err = b.cache.RegisterPlugin(p)
		if err == cache.ErrWrongPluginVersion {
			return nil, fmt.Errorf("%v plugin wrong version.  The "+
				"cache needs to be rebuilt.", v.ID)
		} else if err != nil {
			return nil, fmt.Errorf("cache register plugin '%v': %v",
				v.ID, err)
		}

		log.Infof("Registered plugin: %v", v.ID)
	}

	// Setup pubkey-userid map
	err = b.initUserPubkeys()
	if err != nil {
		return nil, err
	}

	// Setup comment scores map
	err = b.initCommentScores()
	if err != nil {
		return nil, fmt.Errorf("initCommentScore: %v", err)
	}

	// Setup events
	b.initEventManager()

	// Set up the code that checks for paywall payments.
	err = b.initPaywallChecker()
	if err != nil {
		return nil, err
	}

	return b, nil
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

// getProposalSummary returns the proposal summary based on the index markdown file
func getProposalSummary(files []www.File) (string, error) {
	for _, file := range files {
		if file.Name == indexFile {
			return util.GetProposalSummary(file.Payload)
		}
	}
	return "", nil
}

// convertWWWPropCreditFromDatabasePropCredit coverts a database proposal
// credit to a v1 proposal credit.
func convertWWWPropCreditFromDatabasePropCredit(credit database.ProposalCredit) www.ProposalCredit {
	return www.ProposalCredit{
		PaywallID:     credit.PaywallID,
		Price:         credit.Price,
		DatePurchased: credit.DatePurchased,
		TxID:          credit.TxID,
	}
}
