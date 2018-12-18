package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
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
	sync.RWMutex // lock for inventory and comments and caches

	db              database.Database
	cfg             *config
	params          *chaincfg.Params
	client          *http.Client // politeiad client
	eventManager    *EventManager
	userPubkeys     map[string]string               // [pubkey][userid]
	userPaywallPool map[uuid.UUID]paywallPoolMember // [userid][paywallPoolMember]

	// These properties are only used for testing.
	test                   bool
	verificationExpiryTime time.Duration

	// Following entries require locks

	// inventory will eventually replace inventory
	inventory map[string]*inventoryRecord // Current inventory

	// Inventory stats
	numOfCensored        int
	numOfUnvetted        int
	numOfUnvettedChanges int
	numOfPublic          int
	numOfAbandoned       int
	numOfInvalid         int

	// Count of user proposals
	numOfPropsByUserID map[string]int

	// User vote action on each comment
	userLikeActionByCommentID map[string]map[string]map[string]int64 // [token][userid][commentid]action
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

// _convertPropFromInventoryRecord converts a backend inventoryRecord to a front
// end inventoryRecord.
//
// This function must be called WITH the lock held.
func (b *backend) _convertPropFromInventoryRecord(r inventoryRecord) www.ProposalRecord {
	proposal := convertPropFromPD(r.record)

	// Set the comments num.
	proposal.NumComments = uint(len(r.comments))

	// Set the proposals status timestamps
	proposal.PublishedAt,
		proposal.CensoredAt,
		proposal.AbandonedAt = getProposalStatusTimestamps(r)

	// Set the user id.
	var ok bool
	proposal.UserId, ok = b.userPubkeys[proposal.PublicKey]
	if !ok {
		log.Errorf("user not found for public key %v, for proposal %v",
			proposal.PublicKey, proposal.CensorshipRecord.Token)
	}

	return proposal
}

func getProposalStatusTimestamps(ir inventoryRecord) (int64, int64, int64) {
	var publishedAt, censoredAt, abandonedAt int64
	for _, c := range ir.changes {
		switch convertPropStatusFromPD(c.NewStatus) {
		case www.PropStatusPublic:
			publishedAt = c.Timestamp
		case www.PropStatusCensored:
			censoredAt = c.Timestamp
		case www.PropStatusAbandoned:
			abandonedAt = c.Timestamp
		}
	}
	return publishedAt, censoredAt, abandonedAt
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

// remoteInventory fetches the entire inventory of proposals from politeiad.
func (b *backend) remoteInventory() (*pd.InventoryReply, error) {
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}
	inv := pd.Inventory{
		Challenge:     hex.EncodeToString(challenge),
		IncludeFiles:  false,
		VettedCount:   0,
		BranchesCount: 0,
	}

	responseBody, err := b.makeRequest(http.MethodPost, pd.InventoryRoute, inv)
	if err != nil {
		return nil, err
	}

	var ir pd.InventoryReply
	err = json.Unmarshal(responseBody, &ir)
	if err != nil {
		return nil, fmt.Errorf("Unmarshal InventoryReply: %v",
			err)
	}

	err = util.VerifyChallenge(b.cfg.Identity, challenge, ir.Response)
	if err != nil {
		return nil, err
	}
	return &ir, nil
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

// loadInventory calls the politeaid RPC call to load the current inventory.
// Note that this function fakes out the inventory during test and therefore
// must be called WITH the lock held.
func (b *backend) loadInventory() (*pd.InventoryReply, error) {
	if !b.test {
		return b.remoteInventory()
	}

	// Following is test code only.

	// Split the existing inventory into vetted and unvetted.
	//vetted := make([]www.ProposalRecord, 0)
	//unvetted := make([]www.ProposalRecord, 0)

	//for _, v := range b.inventory {
	//	if v.Status == www.PropStatusPublic {
	//		vetted = append(vetted, v)
	//	} else {
	//		unvetted = append(unvetted, v)
	//	}
	//}

	//return &pd.InventoryReply{
	//	Vetted:   convertPropsFromWWW(vetted),
	//	Branches: convertPropsFromWWW(unvetted),
	//}, nil
	return nil, fmt.Errorf("use inventory")
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

// LoadInventory fetches the entire inventory of proposals from politeiad and
// caches it, sorted by most recent timestamp.
func (b *backend) LoadInventory() error {
	b.Lock()
	defer b.Unlock()

	if b.inventory != nil {
		return nil
	}

	// Fetch remote inventory.
	inv, err := b.loadInventory()
	if err != nil {
		return fmt.Errorf("LoadInventory: %v", err)
	}

	err = b.initializeInventory(inv)
	if err != nil {
		return fmt.Errorf("initializeInventory: %v", err)
	}

	log.Infof("Adding %v vetted, %v unvetted proposals to the cache",
		len(inv.Vetted), len(inv.Branches))

	return nil
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

// ProcessAllVetted returns an array of vetted proposals. The maximum number
// of proposals returned is dictated by www.ProposalListPageSize.
func (b *backend) ProcessAllVetted(v www.GetAllVetted) *www.GetAllVettedReply {
	return &www.GetAllVettedReply{
		Proposals: b.getProposals(proposalsRequest{
			After:  v.After,
			Before: v.Before,
			StateMap: map[www.PropStateT]bool{
				www.PropStateVetted: true,
			},
		}),
	}
}

// ProcessAllUnvetted returns an array of all unvetted proposals in reverse order,
// because they're sorted by oldest timestamp first.
func (b *backend) ProcessAllUnvetted(u www.GetAllUnvetted) *www.GetAllUnvettedReply {
	return &www.GetAllUnvettedReply{
		Proposals: b.getProposals(proposalsRequest{
			After:  u.After,
			Before: u.Before,
			StateMap: map[www.PropStateT]bool{
				www.PropStateUnvetted: true,
			},
		}),
	}
}

// ProcessNewProposal tries to submit a new proposal to politeiad.
func (b *backend) ProcessNewProposal(np www.NewProposal, user *database.User) (*www.NewProposalReply, error) {
	log.Tracef("ProcessNewProposal")

	if !b.HasUserPaid(user) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusUserNotPaid,
		}
	}

	if !b.UserHasProposalCredits(user) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusNoProposalCredits,
		}
	}

	err := b.validateProposal(np, user)
	if err != nil {
		return nil, err
	}

	var reply www.NewProposalReply
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	name, err := getProposalName(np.Files)
	if err != nil {
		return nil, err
	}

	// Assemble metdata record
	ts := time.Now().Unix()
	md, err := encodeBackendProposalMetadata(BackendProposalMetadata{
		Version:   BackendProposalMetadataVersion,
		Timestamp: ts,
		Name:      name,
		PublicKey: np.PublicKey,
		Signature: np.Signature,
	})
	if err != nil {
		return nil, err
	}

	n := pd.NewRecord{
		Challenge: hex.EncodeToString(challenge),
		Metadata: []pd.MetadataStream{{
			ID:      mdStreamGeneral,
			Payload: string(md),
		}},
		Files: convertPropFilesFromWWW(np.Files),
	}

	var pdReply pd.NewRecordReply
	if b.test {
		tokenBytes, err := util.Random(pd.TokenSize)
		if err != nil {
			return nil, err
		}

		pdReply.CensorshipRecord = pd.CensorshipRecord{
			Token: hex.EncodeToString(tokenBytes),
		}

		// Add the new proposal to the cache.
		err = b.newInventoryRecord(pd.Record{
			Status:           pd.RecordStatusNotReviewed,
			Timestamp:        ts,
			CensorshipRecord: pdReply.CensorshipRecord,
			Metadata:         n.Metadata,
			Version:          "1",
		})
		if err != nil {
			log.Errorf("ProcessNewProposal could not add record "+
				"into inventory: %v", err)
		}
	} else {
		responseBody, err := b.makeRequest(http.MethodPost,
			pd.NewRecordRoute, n)
		if err != nil {
			return nil, err
		}

		log.Infof("Submitted proposal name: %v", name)
		for k, f := range n.Files {
			log.Infof("%02v: %v %v", k, f.Name, f.Digest)
		}

		err = json.Unmarshal(responseBody, &pdReply)
		if err != nil {
			return nil, fmt.Errorf("Unmarshal NewProposalReply: %v",
				err)
		}

		// Verify the challenge.
		err = util.VerifyChallenge(b.cfg.Identity, challenge, pdReply.Response)
		if err != nil {
			return nil, err
		}

		// Add the new proposal to the inventory cache.
		b.newInventoryRecord(pd.Record{
			Status:           pd.RecordStatusNotReviewed,
			Timestamp:        ts,
			CensorshipRecord: pdReply.CensorshipRecord,
			Metadata:         n.Metadata,
			Version:          "1",
		})
		if err != nil {
			log.Errorf("ProcessNewProposal could not add record "+
				"into inventory: %v", err)
		}
	}

	err = b.SpendProposalCredit(user, pdReply.CensorshipRecord.Token)
	if err != nil {
		return nil, err
	}

	reply.CensorshipRecord = convertPropCensorFromPD(pdReply.CensorshipRecord)

	if !b.test {
		b.fireEvent(EventTypeProposalSubmitted,
			EventDataProposalSubmitted{
				CensorshipRecord: &reply.CensorshipRecord,
				ProposalName:     name,
				User:             user,
			},
		)
	}

	return &reply, nil
}

// ProcessSetProposalStatus changes the status of an existing proposal.
func (b *backend) ProcessSetProposalStatus(sps www.SetProposalStatus, user *database.User) (*www.SetProposalStatusReply, error) {
	log.Tracef("ProcessSetProposalStatus %v", sps.Token)

	err := checkPublicKeyAndSignature(user, sps.PublicKey, sps.Signature,
		sps.Token, strconv.FormatUint(uint64(sps.ProposalStatus), 10),
		sps.StatusChangeMessage)
	if err != nil {
		return nil, err
	}

	// Make sure status change message is not blank if the
	// proposal is being censored or abandoned
	if sps.StatusChangeMessage == "" &&
		(sps.ProposalStatus == www.PropStatusCensored ||
			sps.ProposalStatus == www.PropStatusAbandoned) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusChangeMessageCannotBeBlank,
		}
	}

	// Handle test case
	if b.test {
		var reply www.SetProposalStatusReply
		reply.Proposal.Status = sps.ProposalStatus
		return &reply, nil
	}

	// Create change record
	newStatus := convertPropStatusFromWWW(sps.ProposalStatus)
	r := MDStreamChanges{
		Version:             VersionMDStreamChanges,
		Timestamp:           time.Now().Unix(),
		NewStatus:           newStatus,
		StatusChangeMessage: sps.StatusChangeMessage,
	}

	var ok bool
	r.AdminPubKey, ok = database.ActiveIdentityString(user.Identities)
	if !ok {
		return nil, fmt.Errorf("invalid admin identity: %v",
			user.ID)
	}

	blob, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}

	// Create challenge
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	// XXX Expensive to lock but do it for now.
	// Lock is needed to prevent a race into this record and it
	// needs to be updated in the cache.
	b.Lock()
	defer b.Unlock()

	// Get proposal from inventory
	ir, err := b._getInventoryRecord(sps.Token)
	if err != nil {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusProposalNotFound,
		}
	}
	pr := convertPropFromPD(ir.record)

	// When not in testnet, block admins from changing the
	// status of their own proposals
	if !b.cfg.TestNet {
		if pr.UserId == user.ID.String() {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusReviewerAdminEqualsAuthor,
			}
		}
	}

	var updatedRecord pd.Record
	var challengeResponse string
	switch {
	case pr.State == www.PropStateUnvetted:
		// Unvetted status change

		// Verify status transition is valid
		if pr.Status == www.PropStatusNotReviewed &&
			(sps.ProposalStatus == www.PropStatusCensored ||
				sps.ProposalStatus == www.PropStatusPublic) {
			// allowed; continue
		} else if pr.Status == www.PropStatusUnreviewedChanges &&
			(sps.ProposalStatus == www.PropStatusCensored ||
				sps.ProposalStatus == www.PropStatusPublic) {
			// allowed; continue
		} else {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusInvalidPropStatusTransition,
			}
		}

		// Send unvetted status change request
		sus := pd.SetUnvettedStatus{
			Token:     sps.Token,
			Status:    newStatus,
			Challenge: hex.EncodeToString(challenge),
			MDAppend: []pd.MetadataStream{
				{
					ID:      mdStreamChanges,
					Payload: string(blob),
				},
			},
		}

		responseBody, err := b.makeRequest(http.MethodPost,
			pd.SetUnvettedStatusRoute, sus)
		if err != nil {
			return nil, err
		}

		var susr pd.SetUnvettedStatusReply
		err = json.Unmarshal(responseBody, &susr)
		if err != nil {
			return nil, fmt.Errorf("Could not unmarshal "+
				"SetUnvettedStatusReply: %v", err)
		}
		updatedRecord = susr.Record
		challengeResponse = susr.Response

	case pr.State == www.PropStateVetted:
		// Vetted status change

		// We only allow a transition from public to abandoned
		if pr.Status != www.PropStatusPublic ||
			sps.ProposalStatus != www.PropStatusAbandoned {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusInvalidPropStatusTransition,
			}
		}

		// Ensure voting has not been started or authorized yet
		if ir.voting.StartBlockHeight != "" ||
			voteIsAuthorized(ir) {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusWrongVoteStatus,
			}
		}

		// Send vetted status change request
		svs := pd.SetVettedStatus{
			Token:     sps.Token,
			Status:    newStatus,
			Challenge: hex.EncodeToString(challenge),
			MDAppend: []pd.MetadataStream{
				{
					ID:      mdStreamChanges,
					Payload: string(blob),
				},
			},
		}

		responseBody, err := b.makeRequest(http.MethodPost,
			pd.SetVettedStatusRoute, svs)
		if err != nil {
			return nil, err
		}

		var svsr pd.SetVettedStatusReply
		err = json.Unmarshal(responseBody, &svsr)
		if err != nil {
			return nil, fmt.Errorf("Could not unmarshal "+
				"SetVettedStatusReply: %v", err)
		}
		updatedRecord = svsr.Record
		challengeResponse = svsr.Response

	default:
		return nil, fmt.Errorf("Invalid proposal state %v: %v",
			pr.State, pr.CensorshipRecord.Token)
	}

	// Verify the challenge.
	err = util.VerifyChallenge(b.cfg.Identity, challenge,
		challengeResponse)
	if err != nil {
		return nil, err
	}

	// politeiad returns the record without the files
	// attached. Add files back onto the record.
	updatedRecord.Files = ir.record.Files

	// Update the inventory with the metadata changes.
	err = b._updateInventoryRecord(updatedRecord)
	if err != nil {
		return nil, fmt.Errorf("updateInventoryRecord %v", err)
	}

	// Fire off proposal status change event
	updatedProp := convertPropFromPD(updatedRecord)
	b.eventManager._fireEvent(EventTypeProposalStatusChange,
		EventDataProposalStatusChange{
			Proposal:          &updatedProp,
			AdminUser:         user,
			SetProposalStatus: &sps,
		},
	)

	return &www.SetProposalStatusReply{
		Proposal: updatedProp,
	}, nil
}

// ProcessProposalDetails tries to fetch the full details of a proposal from politeiad.
func (b *backend) ProcessProposalDetails(propDetails www.ProposalsDetails, user *database.User) (*www.ProposalDetailsReply, error) {
	log.Debugf("ProcessProposalDetails")

	var reply www.ProposalDetailsReply
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	b.RLock()
	p, err := b._getInventoryRecord(propDetails.Token)
	if err != nil {
		b.RUnlock()
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusProposalNotFound,
		}
	}
	cachedProposal := b._convertPropFromInventoryRecord(p)
	b.RUnlock()

	// validate requested version when it is specified
	if propDetails.Version != "" {
		latestVersion, err := strconv.ParseUint(cachedProposal.Version, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("Could not parse proposal version %v: %v",
				propDetails.Token, err)
		}
		specVersion, err := strconv.ParseUint(propDetails.Version, 10, 64)
		if err != nil || specVersion > latestVersion || specVersion == 0 {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusInvalidPropVersion,
			}
		}
	}

	var isVettedProposal bool
	var requestObject interface{}
	if cachedProposal.State == www.PropStateVetted {
		isVettedProposal = true
		requestObject = pd.GetVetted{
			Token:     propDetails.Token,
			Version:   propDetails.Version,
			Challenge: hex.EncodeToString(challenge),
		}
	} else {
		isVettedProposal = false
		requestObject = pd.GetUnvetted{
			Token:     propDetails.Token,
			Challenge: hex.EncodeToString(challenge),
		}
	}

	if b.test {
		reply.Proposal = cachedProposal
		return &reply, nil
	}

	// The title and files for unvetted proposals should not be viewable by
	// non-admins; only the proposal meta data (status, censorship data,
	// etc) should be publicly viewable.
	isUserAdmin := user != nil && user.Admin

	var isUserTheAuthor bool
	if user != nil {
		authorID, err := uuid.Parse(cachedProposal.UserId)
		if err != nil {
			// Only complain and move on since some of the
			// proposals details can still be sent for a non-admin
			// or a non-author user
			log.Infof("ProcessProposalDetails: ParseUint failed "+
				"on '%v': %v", cachedProposal.UserId, err)
		}

		isUserTheAuthor = authorID == user.ID
	}

	if !isVettedProposal && !isUserAdmin && !isUserTheAuthor {
		reply.Proposal = www.ProposalRecord{
			Status:           cachedProposal.Status,
			Timestamp:        cachedProposal.Timestamp,
			PublicKey:        cachedProposal.PublicKey,
			Signature:        cachedProposal.Signature,
			CensorshipRecord: cachedProposal.CensorshipRecord,
			NumComments:      cachedProposal.NumComments,
			UserId:           cachedProposal.UserId,
			Username:         b.getUsernameById(cachedProposal.UserId),
		}
		return &reply, nil
	}

	var route string
	if isVettedProposal {
		route = pd.GetVettedRoute
	} else {
		route = pd.GetUnvettedRoute
	}

	responseBody, err := b.makeRequest(http.MethodPost, route, requestObject)
	if err != nil {
		return nil, err
	}

	var response string
	var fullRecord pd.Record
	if isVettedProposal {
		var pdReply pd.GetVettedReply
		err = json.Unmarshal(responseBody, &pdReply)
		if err != nil {
			return nil, fmt.Errorf("Could not unmarshal "+
				"GetVettedReply: %v", err)
		}

		response = pdReply.Response
		fullRecord = pdReply.Record
	} else {
		var pdReply pd.GetUnvettedReply
		err = json.Unmarshal(responseBody, &pdReply)
		if err != nil {
			return nil, fmt.Errorf("Could not unmarshal "+
				"GetUnvettedReply: %v", err)
		}

		response = pdReply.Response
		fullRecord = pdReply.Record
	}

	// Verify the challenge.
	err = util.VerifyChallenge(b.cfg.Identity, challenge, response)
	if err != nil {
		return nil, err
	}

	b.RLock()
	reply.Proposal = b._convertPropFromInventoryRecord(inventoryRecord{
		record:   fullRecord,
		changes:  p.changes,
		comments: p.comments,
	})
	b.RUnlock()

	reply.Proposal.Username = b.getUsernameById(reply.Proposal.UserId)

	return &reply, nil
}

// ProcessComment processes a submitted comment.  It ensures the proposal and
// the parent exists.  A parent ID of 0 indicates that it is a comment on the
// proposal whereas non-zero indicates that it is a reply to a comment.
func (b *backend) ProcessComment(c www.NewComment, user *database.User) (*www.NewCommentReply, error) {
	log.Debugf("ProcessComment: %v %v", c.Token, user.ID)

	// Pay up sucker!
	if !b.HasUserPaid(user) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusUserNotPaid,
		}
	}

	// Verify authenticity.
	err := checkPublicKeyAndSignature(user, c.PublicKey, c.Signature,
		c.Token, c.ParentID, c.Comment)
	if err != nil {
		return nil, err
	}

	// Note that we are not racing ir because it is a copy.
	ir, err := b.getInventoryRecord(c.Token)
	if err != nil {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusProposalNotFound,
		}
	}

	// make sure the proposal is public
	if convertPropStatusFromPD(ir.record.Status) != www.PropStatusPublic {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusCannotCommentOnProp,
		}
	}

	// make sure the proposal voting has not ended
	bb, err := b.getBestBlock()
	if err != nil {
		return nil, fmt.Errorf("ProcessComment: getBestBlock: %v", err)
	}

	if getVoteStatus(ir, bb) == www.PropVoteStatusFinished {
		// vote is finished
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusCannotCommentOnProp,
		}
	}

	// Validate comment
	if err := validateComment(c); err != nil {
		return nil, err
	}

	// Setup plugin command
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	ndc := convertWWWNewCommentToDecredNewComment(c)
	payload, err := decredplugin.EncodeNewComment(ndc)
	if err != nil {
		return nil, err
	}

	pc := pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        decredplugin.ID,
		Command:   decredplugin.CmdNewComment,
		CommandID: decredplugin.CmdNewComment,
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
	ncr, err := decredplugin.DecodeNewCommentReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}

	// Note this call takes the read lock.
	ncrWWW := b.convertDecredNewCommentReplyToWWWNewCommentReply(*ncr)

	// set author username
	ncrWWW.Comment.Username = b.getUsernameById(ncrWWW.Comment.UserID)

	err = b.setRecordComment(ncrWWW.Comment)
	if err != nil {
		return nil, fmt.Errorf("setRecordComment %v", err)
	}

	if !b.test {
		b.fireEvent(EventTypeComment, EventDataComment{
			Comment: &ncrWWW.Comment,
		})
	}

	return &ncrWWW, nil
}

// ProcessLikeComment processes a up or down vote of a comment.
func (b *backend) ProcessLikeComment(lc www.LikeComment, user *database.User) (*www.LikeCommentReply, error) {
	log.Debugf("ProcessLikeComment: %v %v", lc.Token, user.ID)

	// Pay up sucker!
	if !b.HasUserPaid(user) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusUserNotPaid,
		}
	}

	// Verify authenticity.
	err := checkPublicKeyAndSignature(user, lc.PublicKey, lc.Signature,
		lc.Token, lc.CommentID, lc.Action)
	if err != nil {
		return nil, err
	}

	// get the proposal record from inventory
	b.RLock()
	ir, err := b._getInventoryRecord(lc.Token)
	b.RUnlock()
	if err != nil {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusProposalNotFound,
		}
	}

	// Verify comment exists
	_, ok := ir.comments[lc.CommentID]
	if !ok {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusCommentNotFound,
		}
	}

	// Ensure proposal is public
	pr := convertPropFromPD(ir.record)
	if pr.Status != www.PropStatusPublic {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusWrongStatus,
		}
	}

	// make sure the proposal voting has not ended
	bb, err := b.getBestBlock()
	if err != nil {
		return nil, fmt.Errorf("ProcessLikeComment: getBestBlock: %v", err)
	}

	if getVoteStatus(ir, bb) == www.PropVoteStatusFinished {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusCannotVoteOnPropComment,
		}
	}

	// Validate action
	action := lc.Action
	if len(lc.Action) > 10 {
		// Clip action to not fill up logs and prevent dos of sorts.
		action = lc.Action[0:9] + "..."
	}
	switch action {
	case "1":
	case "-1":
	default:
		return nil, fmt.Errorf("invalid LikeComment action: %v", action)
	}

	// Setup plugin command
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	nlc := convertWWWLikeCommentToDecredLikeComment(lc)
	payload, err := decredplugin.EncodeLikeComment(nlc)
	if err != nil {
		return nil, err
	}

	pc := pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        decredplugin.ID,
		Command:   decredplugin.CmdLikeComment,
		CommandID: decredplugin.CmdLikeComment,
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
	lcr, err := decredplugin.DecodeLikeCommentReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}

	comment, err := b.updateResultsForCommentLike(lc)
	if err != nil {
		return nil, err
	}

	lcrWWW := www.LikeCommentReply{
		Total:   comment.TotalVotes,
		Result:  comment.ResultVotes,
		Receipt: lcr.Receipt,
		Error:   lcr.Error,
	}

	return &lcrWWW, nil
}

func (b *backend) ProcessCensorComment(cc www.CensorComment, user *database.User) (*www.CensorCommentReply, error) {
	log.Debugf("ProcessCensorComment: %v: %v", cc.Token, cc.CommentID)

	// Verify authenticity.
	err := checkPublicKeyAndSignature(user, cc.PublicKey, cc.Signature,
		cc.Token, cc.CommentID, cc.Reason)
	if err != nil {
		return nil, err
	}

	// Ensure censor reason is present.
	if cc.Reason == "" {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusCensorReasonCannotBeBlank,
		}
	}

	// get the proposal record from inventory
	b.RLock()
	ir, err := b._getInventoryRecord(cc.Token)
	if err != nil {
		b.RUnlock()
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusProposalNotFound,
		}
	}

	// Ensure comment exists and has not already been censored.
	c, err := b._getInventoryRecordComment(cc.Token, cc.CommentID)
	if err != nil {
		b.RUnlock()
		return nil, fmt.Errorf("comment not found %v: %v",
			cc.Token, cc.CommentID)
	}
	b.RUnlock()
	if c.Censored {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusCannotCensorComment,
		}
	}

	// Ensure proposal voting has not ended.
	bb, err := b.getBestBlock()
	if err != nil {
		return nil, fmt.Errorf("getBestBlock: %v", err)
	}

	if getVoteStatus(ir, bb) == www.PropVoteStatusFinished {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusCannotCensorComment,
		}
	}

	// Setup plugin command.
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	dcc := convertWWWCensorCommentToDecredCensorComment(cc)
	payload, err := decredplugin.EncodeCensorComment(dcc)
	if err != nil {
		return nil, fmt.Errorf("EncodeCensorComment: %v", err)
	}

	pc := pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        decredplugin.ID,
		Command:   decredplugin.CmdCensorComment,
		CommandID: decredplugin.CmdCensorComment,
		Payload:   string(payload),
	}

	// Send plugin request.
	responseBody, err := b.makeRequest(http.MethodPost,
		pd.PluginCommandRoute, pc)
	if err != nil {
		return nil, fmt.Errorf("makeRequest: %v", err)
	}

	var reply pd.PluginCommandReply
	err = json.Unmarshal(responseBody, &reply)
	if err != nil {
		return nil, fmt.Errorf("Unmarshal PluginCommandReply: %v", err)
	}

	// Verify the challenge.
	err = util.VerifyChallenge(b.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return nil, fmt.Errorf("VerifyChallenge: %v", err)
	}

	// Decode plugin reply.
	ccr, err := decredplugin.DecodeCensorCommentReply([]byte(reply.Payload))
	if err != nil {
		return nil, fmt.Errorf("DecodeCensorCommentReply: %v", err)
	}
	ccrWWW := convertDecredCensorCommentReplyToWWWCensorCommentReply(*ccr)

	// Update inventory cache.
	b.Lock()
	defer b.Unlock()
	c, err = b._getInventoryRecordComment(cc.Token, cc.CommentID)
	if err != nil {
		return nil, fmt.Errorf("comment not found %v: %v", cc.Token,
			cc.CommentID)
	}

	// Reset comment in cache
	c.Comment = ""
	c.Censored = true
	err = b._setRecordComment(*c)
	if err != nil {
		return nil, fmt.Errorf("setRecordComment %v", err)
	}

	return &ccrWWW, nil
}

// ProcessCommentGet returns all comments for a given proposal. If the user
// is logged in, returns the user's last access time for the given proposal.
// Else, returns 0 as the access time
func (b *backend) ProcessCommentGet(token string, user *database.User) (*www.GetCommentsReply, error) {
	log.Debugf("ProcessCommentGet: %v", token)
	// get comments
	c, err := b.getComments(token)
	if err != nil {
		return nil, err
	}

	if user != nil {
		// gets the last accesstime for the given proposal
		if user.ProposalCommentsAccessTimes != nil {
			c.AccessTime = user.ProposalCommentsAccessTimes[token]
		} else {
			user.ProposalCommentsAccessTimes = make(map[string]int64)
		}
		user.ProposalCommentsAccessTimes[token] = time.Now().Unix()
		err = b.db.UserUpdate(*user)
		if err != nil {
			return nil, err
		}
	}
	return c, nil
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

// ProcessUserProposals returns the proposals for the given user.
func (b *backend) ProcessUserProposals(up *www.UserProposals, isCurrentUser, isAdminUser bool) (*www.UserProposalsReply, error) {
	// Verify user exists
	_, err := b.getUserByIDStr(up.UserId)
	if err != nil {
		return nil, err
	}

	// Get user proposal data
	ps := b.userProposalStats(up.UserId)
	numProposals := ps.NumOfPublic + ps.NumOfAbandoned
	if isCurrentUser || isAdminUser {
		numProposals += ps.NumOfUnvetted + ps.NumOfUnvettedChanges +
			ps.NumOfCensored
	}

	return &www.UserProposalsReply{
		Proposals: b.getProposals(proposalsRequest{
			After:  up.After,
			Before: up.Before,
			UserId: up.UserId,
			StateMap: map[www.PropStateT]bool{
				www.PropStateUnvetted: isCurrentUser || isAdminUser,
				www.PropStateVetted:   true,
			},
		}),
		NumOfProposals: numProposals,
	}, nil
}

func (b *backend) ProcessActiveVote() (*www.ActiveVoteReply, error) {
	log.Tracef("ProcessActiveVote")

	//  We need to determine best block height here and only return active
	//  votes.

	bestBlock, err := b.getBestBlock()
	if err != nil {
		return nil, err
	}

	b.RLock()
	defer b.RUnlock()

	// iterate over all props and see what is active
	var avr www.ActiveVoteReply
	for _, i := range b.inventory {
		// Use StartBlockHeight as a canary
		if len(i.voting.StartBlockHeight) == 0 {
			continue
		}
		ee, err := strconv.ParseUint(i.voting.EndHeight, 10, 64)
		if err != nil {
			log.Errorf("invalid ee, should not happen: %v", err)
			continue
		}
		if bestBlock > ee {
			// expired vote
			continue
		}

		avr.Votes = append(avr.Votes, www.ProposalVoteTuple{
			Proposal:       convertPropFromPD(i.record),
			StartVote:      i.votebits,
			StartVoteReply: i.voting,
		})
	}

	return &avr, nil
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

	// Get inventory record
	ir, err := b.getInventoryRecord(av.Token)
	if err != nil {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusProposalNotFound,
		}
	}

	// Verify signature authenticity
	err = checkPublicKeyAndSignature(user, av.PublicKey, av.Signature,
		av.Token, ir.record.Version, av.Action)
	if err != nil {
		return nil, err
	}

	// Verify record is in the right state and that the
	// authorize vote request is valid
	switch {
	case ir.record.Status != pd.RecordStatusPublic:
		// Record not public
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusWrongStatus,
		}
	case ir.voting.StartBlockHeight != "":
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
		voteIsAuthorized(ir):
		// Cannot authorize vote; vote has already been
		// authorized
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVoteAlreadyAuthorized,
		}
	case av.Action == www.AuthVoteActionRevoke &&
		!voteIsAuthorized(ir):
		// Cannot revoke authorization; vote has not been
		// authorized
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVoteNotAuthorized,
		}
	case ir.proposalMD.PublicKey != av.PublicKey:
		// User is not the author. First make sure the author didn't
		// submit the proposal using an old identity.
		b.RLock()
		userID, ok := b.userPubkeys[ir.proposalMD.PublicKey]
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
	avrWWW := convertAuthorizeVoteReplyFromDecredplugin(*avr)

	// Update inventory cache
	err = b.setRecordVoteAuthorization(av.Token, avrWWW)
	if err != nil {
		return nil, fmt.Errorf("setRecordVoteAuthorization: %v", err)
	}

	if !b.test && av.Action == www.AuthVoteActionAuthorize {
		b.fireEvent(EventTypeProposalVoteAuthorized,
			EventDataProposalVoteAuthorized{
				AuthorizeVote: &av,
				User:          user,
			},
		)
	}

	return &avrWWW, nil
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

	// For now we lock the struct but this needs to be peeled apart.  The
	// start voting call is expensive and that needs to be handled without
	// the mutex held.
	b.Lock()
	defer b.Unlock()

	// Look up record
	ir, err := b._getInventoryRecord(sv.Vote.Token)
	if err != nil {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusProposalNotFound,
		}
	}

	// Ensure record is public, vote has been authorized,
	// and vote has not already started.
	if ir.record.Status != pd.RecordStatusPublic {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusWrongStatus,
		}
	}
	if !voteIsAuthorized(ir) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVoteNotAuthorized,
		}
	}
	if ir.voting.StartBlockHeight != "" {
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

	voting := convertStartVoteReplyFromDecredplugin(*vr)
	err = b._setRecordVoting(sv.Vote.Token, sv, voting)
	if err != nil {
		return nil, fmt.Errorf("setRecordVoting %v", err)
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
	rv := voting
	return &rv, nil
}

func (b *backend) ProcessVoteResults(token string) (*www.VoteResultsReply, error) {
	log.Tracef("ProcessVoteResults")

	// Fetch record from inventory in order to get the voting details
	// (StartVoteReply)
	ir, err := b.getInventoryRecord(token)
	if err != nil {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusProposalNotFound,
		}
	}
	if ir.record.Status != pd.RecordStatusPublic {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusWrongStatus,
		}
	}

	vrr, err := b.getVoteResultsFromPlugin(token)
	if err != nil {
		return nil, err
	}

	wvrr := convertVoteResultsReplyFromDecredplugin(*vrr, ir)
	return &wvrr, nil
}

// ProcessGetAllVoteStatus returns the vote status of all public proposals
func (b *backend) ProcessGetAllVoteStatus() (*www.GetAllVoteStatusReply, error) {
	log.Tracef("ProcessGetAllVoteStatus")

	// We need to determine best block height here in order to set
	// the voting status
	bestBlock, err := b.getBestBlock()
	if err != nil {
		return nil, err
	}

	b.RLock()
	defer b.RUnlock()

	// iterate over all props and see what is public
	var gavsr www.GetAllVoteStatusReply
	gavsr.VotesStatus = make([]www.VoteStatusReply, 0)
	for _, i := range b.inventory {

		ps := convertPropStatusFromPD(i.record.Status)
		if ps != www.PropStatusPublic {
			// proposal isn't public
			continue
		}

		vrr, err := b.getVoteResultsFromPlugin(i.record.CensorshipRecord.Token)
		if err != nil {
			return nil, err
		}

		vsr := www.VoteStatusReply{
			Token:              i.record.CensorshipRecord.Token,
			Status:             getVoteStatus(*i, bestBlock),
			TotalVotes:         uint64(len(vrr.CastVotes)),
			OptionsResult:      convertVoteResultsFromDecredplugin(*vrr),
			EndHeight:          i.voting.EndHeight,
			NumOfEligibleVotes: len(i.voting.EligibleTickets),
			QuorumPercentage:   vrr.StartVote.Vote.QuorumPercentage,
			PassPercentage:     vrr.StartVote.Vote.PassPercentage,
		}

		gavsr.VotesStatus = append(gavsr.VotesStatus, vsr)
	}

	return &gavsr, nil
}

// ProcessVoteStatus returns the vote status for a given proposal
func (b *backend) ProcessVoteStatus(token string) (*www.VoteStatusReply, error) {
	log.Tracef("ProcessProposalVotingStatus")

	ir, err := b.getInventoryRecord(token)
	if err != nil {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusProposalNotFound,
		}
	}
	if ir.record.Status != pd.RecordStatusPublic {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusWrongStatus,
		}
	}

	bestBlock, err := b.getBestBlock()
	if err != nil {
		return nil, err
	}

	vrr, err := b.getVoteResultsFromPlugin(token)
	if err != nil {
		return nil, err
	}

	return &www.VoteStatusReply{
		Token:              token,
		TotalVotes:         uint64(len(vrr.CastVotes)),
		Status:             getVoteStatus(ir, bestBlock),
		OptionsResult:      convertVoteResultsFromDecredplugin(*vrr),
		EndHeight:          ir.voting.EndHeight,
		NumOfEligibleVotes: len(ir.voting.EligibleTickets),
		QuorumPercentage:   vrr.StartVote.Vote.QuorumPercentage,
		PassPercentage:     vrr.StartVote.Vote.PassPercentage,
	}, nil
}

// ProcessUserCommentsLikes returns the votes an user has for the comments of a given proposal
func (b *backend) ProcessUserCommentsLikes(user *database.User, token string) (*www.UserCommentsLikesReply, error) {
	log.Tracef("ProcessUserCommentsLikes")

	userID := user.ID.String()
	uclr := www.UserCommentsLikesReply{}
	b.RLock()
	defer b.RUnlock()

	userLikeActions := b.userLikeActionByCommentID[token][userID]

	for commentID, action := range userLikeActions {
		uclr.CommentsLikes = append(uclr.CommentsLikes, www.CommentLike{
			Action:    strconv.FormatInt(action, 10),
			CommentID: commentID,
			Token:     token,
		})
	}

	return &uclr, nil
}

// ProcessEditProposal attempts to edit a proposal on politeiad
func (b *backend) ProcessEditProposal(user *database.User, ep www.EditProposal) (*www.EditProposalReply, error) {
	log.Tracef("ProcessEditProposal %v", ep.Token)

	// verify that the proposal voting has not started
	// This is expensive so do it outside of the lock.
	bb, err := b.getBestBlock()
	if err != nil {
		return nil, err
	}

	// it is ok to race invRecord.
	// In theory the user can not issue racing edit prop commands. In
	// practice a network hickup can submit the same edit twice but then
	// the decred plugin should reject the second call as "no changes".
	// A malicious user that alters the code to issue concurrent updates
	// could result in an out-of-order cache update.
	// Politeaid will remain coherent.
	b.RLock()
	// get current proposal record from inventory
	invRecord, err := b._getInventoryRecord(ep.Token)
	if err != nil {
		b.RUnlock()
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusProposalNotFound,
		}
	}
	cachedProposal := b._convertPropFromInventoryRecord(invRecord)

	// verify if the user is the proposal owner
	authorIDStr, ok := b.userPubkeys[cachedProposal.PublicKey]
	if !ok {
		b.RUnlock()
		return nil, fmt.Errorf("public key not found %v",
			cachedProposal.PublicKey)
	}
	b.RUnlock()

	authorID, err := uuid.Parse(authorIDStr)
	if err != nil {
		return nil, err
	}
	if authorID != user.ID {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusUserActionNotAllowed,
		}
	}

	// Validate proposal vote status
	voteStatus := getVoteStatus(invRecord, bb)
	if voteStatus != www.PropVoteStatusNotAuthorized {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusWrongVoteStatus,
		}
	}

	// validate proposal
	//
	// convert it to www.NewProposal so the we can reuse
	// the function backend/validateProposal
	np := www.NewProposal{
		Files:     ep.Files,
		PublicKey: ep.PublicKey,
		Signature: ep.Signature,
	}
	err = b.validateProposal(np, user)
	if err != nil {
		return nil, err
	}

	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	name, err := getProposalName(ep.Files)
	if err != nil {
		return nil, err
	}

	// Assemble metadata record
	ts := time.Now().Unix()
	backendMetadata := BackendProposalMetadata{
		Version:   BackendProposalMetadataVersion,
		Timestamp: ts,
		Name:      name,
		PublicKey: ep.PublicKey,
		Signature: ep.Signature,
	}
	md, err := encodeBackendProposalMetadata(backendMetadata)
	if err != nil {
		return nil, err
	}

	mds := []pd.MetadataStream{{
		ID:      mdStreamGeneral,
		Payload: string(md),
	}}

	var delFiles []string
	for _, v := range invRecord.record.Files {
		found := false
		for _, c := range ep.Files {
			if v.Name == c.Name {
				found = true
			}
		}
		if !found {
			delFiles = append(delFiles, v.Name)
		}
	}

	e := pd.UpdateRecord{
		Token:       ep.Token,
		Challenge:   hex.EncodeToString(challenge),
		MDOverwrite: mds,
		FilesAdd:    convertPropFilesFromWWW(ep.Files),
		FilesDel:    delFiles,
	}

	var pdRoute string

	if cachedProposal.Status == www.PropStatusNotReviewed ||
		cachedProposal.Status == www.PropStatusUnreviewedChanges {
		pdRoute = pd.UpdateUnvettedRoute
	} else if cachedProposal.Status == www.PropStatusPublic {
		pdRoute = pd.UpdateVettedRoute
	} else {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusWrongStatus,
		}
	}

	responseBody, err := b.makeRequest(http.MethodPost,
		pdRoute, e)
	if err != nil {
		return nil, err
	}

	var pdReply pd.UpdateRecordReply
	err = json.Unmarshal(responseBody, &pdReply)
	if err != nil {
		return nil, fmt.Errorf("Unmarshal UpdateUnvettedReply: %v",
			err)
	}

	b.Lock()
	defer b.Unlock()

	// Delete vote authorization if one existed before the edit
	if invRecord.voteAuthorization.Receipt != "" {
		err = b._setRecordVoteAuthorization(ep.Token,
			www.AuthorizeVoteReply{})
		if err != nil {
			// This should be impossible and we can't fail here
			log.Criticalf("setRecordVoteAuthorization: %v", err)
		}
	}

	// update inventory record
	err = b._updateInventoryRecord(pdReply.Record)
	if err != nil {
		return nil, fmt.Errorf("ProcessEditProposal: "+
			"updateInventoryRecord %v", err)
	}

	reply := &www.EditProposalReply{
		Proposal: convertPropFromPD(pdReply.Record),
	}

	if !b.test {
		b.eventManager._fireEvent(EventTypeProposalEdited,
			EventDataProposalEdited{
				Proposal: &reply.Proposal,
			},
		)
	}

	return reply, nil
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
		ValidMIMETypes:             www.PolicyValidMimeTypes,
		MinProposalNameLength:      www.PolicyMinProposalNameLength,
		MaxProposalNameLength:      www.PolicyMaxProposalNameLength,
		ProposalNameSupportedChars: www.PolicyProposalNameSupportedChars,
		MaxCommentLength:           www.PolicyMaxCommentLength,
	}
}

// ProcessProposalStats returns the counting of proposals aggrouped by each
// proposal status
// Must be called WITHOUT holding the mutex.
func (b *backend) ProcessProposalsStats() www.ProposalsStatsReply {
	ps := b.inventoryProposalStats()
	return www.ProposalsStatsReply{
		NumOfCensored:        ps.NumOfCensored,
		NumOfUnvetted:        ps.NumOfUnvetted,
		NumOfUnvettedChanges: ps.NumOfUnvettedChanges,
		NumOfPublic:          ps.NumOfPublic,
		NumOfAbandoned:       ps.NumOfAbandoned,
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

// getVoteResultsFromPlugin fetches the vote results for a given proposal
func (b *backend) getVoteResultsFromPlugin(token string) (*decredplugin.VoteResultsReply, error) {

	payload, err := decredplugin.EncodeVoteResults(decredplugin.VoteResults{
		Token: token,
	})
	if err != nil {
		return nil, err
	}

	// Obtain vote results from plugin
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	pc := pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        decredplugin.ID,
		Command:   decredplugin.CmdProposalVotes,
		CommandID: decredplugin.CmdProposalVotes + " " + token,
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

	vrr, err := decredplugin.DecodeVoteResultsReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}

	return vrr, nil
}

// NewBackend creates a new backend context for use in www and tests.
func NewBackend(cfg *config) (*backend, error) {
	// Setup database.
	//localdb.UseLogger(localdbLog)
	db, err := localdb.New(cfg.DataDir)
	if err != nil {
		return nil, err
	}

	// Context
	b := &backend{
		db:                        db,
		cfg:                       cfg,
		userPubkeys:               make(map[string]string),
		userPaywallPool:           make(map[uuid.UUID]paywallPoolMember),
		numOfPropsByUserID:        make(map[string]int),
		userLikeActionByCommentID: make(map[string]map[string]map[string]int64),
	}

	// Setup pubkey-userid map
	err = b.initUserPubkeys()
	if err != nil {
		return nil, err
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

// voteIsAuthorized returns whether the author of an inventory record has
// authorized an admin to start the voting period on the record.
func voteIsAuthorized(ir inventoryRecord) bool {
	if ir.voteAuthorization.Receipt == "" {
		// Vote has not been authorized yet
		return false
	} else if ir.voteAuthorization.Action == www.AuthVoteActionRevoke {
		// Vote authorization was revoked
		return false
	}
	return true
}

func getVoteStatus(ir inventoryRecord, bestBlock uint64) www.PropVoteStatusT {
	if ir.voting.StartBlockHeight == "" {
		if voteIsAuthorized(ir) {
			return www.PropVoteStatusAuthorized
		} else {
			return www.PropVoteStatusNotAuthorized
		}
	}

	ee, err := strconv.ParseUint(ir.voting.EndHeight, 10, 64)
	if err != nil {
		log.Errorf("invalid ee, should not happen: %v", err)
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
func convertWWWPropCreditFromDatabasePropCredit(credit database.ProposalCredit) www.ProposalCredit {
	return www.ProposalCredit{
		PaywallID:     credit.PaywallID,
		Price:         credit.Price,
		DatePurchased: credit.DatePurchased,
		TxID:          credit.TxID,
	}
}
