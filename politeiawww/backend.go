package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/decred/politeia/politeiawww/api/v1"

	"golang.org/x/crypto/bcrypt"

	"github.com/dajohi/goemail"
	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrtime/merkle"
	"github.com/decred/politeia/decredplugin"
	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/api/v1/mime"
	www "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/database"
	"github.com/decred/politeia/politeiawww/database/localdb"
	"github.com/decred/politeia/util"
)

const (
	// indexFile contains the file name of the index file
	indexFile = "index.md"

	// mdStream* indicate the metadata stream used for various types
	mdStreamGeneral = 0 // General information for this proposal
	mdStreamChanges = 2 // Changes to record
	// Note that 13 is in use by the decred plugin
	// Note that 14 is in use by the decred plugin
	// Note that 15 is in use by the decred plugin
)

type MDStreamChanges struct {
	AdminPubKey string           // Identity of the administrator
	NewStatus   pd.RecordStatusT // NewStatus
	Timestamp   int64            // Timestamp of the change
}

// politeiawww backend construct
type backend struct {
	sync.RWMutex // lock for inventory and comments

	db          database.Database
	cfg         *config
	params      *chaincfg.Params
	client      *http.Client      // politeiad client
	userPubkeys map[string]string // [pubkey][userid]

	// These properties are only used for testing.
	test                   bool
	verificationExpiryTime time.Duration

	// Following entries require locks

	// inventory will eventually replace inventory
	inventory map[string]*inventoryRecord // Current inventory
}

const (
	BackendProposalMetadataVersion = 1

	politeiaMailName = "Politeia"
)

var (
	validUsername = regexp.MustCompile(createUsernameRegex())
)

type BackendProposalMetadata struct {
	Version   uint64 `json:"version"`   // BackendProposalMetadata version
	Timestamp int64  `json:"timestamp"` // Last update of proposal
	Name      string `json:"name"`      // Generated proposal name
	PublicKey string `json:"publickey"` // Key used for signature.
	Signature string `json:"signature"` // Signature of merkle root
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
	userId, err := strconv.ParseUint(userIdStr, 10, 64)
	if err != nil {
		return ""
	}

	user, err := b.db.UserGetById(userId)
	if err != nil {
		return ""
	}

	return user.Username
}

// initUserPubkeys initializes the userPubkeys map with all the pubkey-userid
// associations that are found in the database.
//
// This function must be called WITHOUT the lock held.
func (b *backend) initUserPubkeys() error {
	b.Lock()
	defer b.Unlock()

	return b.db.AllUsers(func(u *database.User) {
		userId := strconv.FormatUint(u.ID, 10)
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

	userId := strconv.FormatUint(user.ID, 10)
	b.userPubkeys[publicKey] = userId
}

// emailNewUserVerificationLink emails the link with the new user verification token
// if the email server is set up.
func (b *backend) emailNewUserVerificationLink(email, token string) error {
	if b.cfg.SMTP == nil {
		return nil
	}

	l, err := url.Parse(b.cfg.WebServerAddress + www.RouteVerifyNewUser)
	if err != nil {
		return err
	}
	q := l.Query()
	q.Set("email", email)
	q.Set("verificationtoken", token)
	l.RawQuery = q.Encode()

	var buf bytes.Buffer
	tplData := newUserEmailTemplateData{
		Email: email,
		Link:  l.String(),
	}
	err = templateNewUserEmail.Execute(&buf, &tplData)
	if err != nil {
		return err
	}
	from := "noreply@decred.org"
	subject := "Verify Your Email"
	body := buf.String()

	msg := goemail.NewHTMLMessage(from, subject, body)
	msg.AddTo(email)

	msg.SetName(politeiaMailName)
	return b.cfg.SMTP.Send(msg)
}

// emailResetPasswordVerificationLink emails the link with the reset password
// verification token if the email server is set up.
func (b *backend) emailResetPasswordVerificationLink(email, token string) error {
	if b.cfg.SMTP == nil {
		return nil
	}

	l, err := url.Parse(b.cfg.WebServerAddress + www.RouteResetPassword)
	if err != nil {
		return err
	}
	q := l.Query()
	q.Set("email", email)
	q.Set("verificationtoken", token)
	l.RawQuery = q.Encode()

	var buf bytes.Buffer
	tplData := resetPasswordEmailTemplateData{
		Email: email,
		Link:  l.String(),
	}
	err = templateResetPasswordEmail.Execute(&buf, &tplData)
	if err != nil {
		return err
	}
	from := "noreply@decred.org"
	subject := "Reset Your Password"
	body := buf.String()

	msg := goemail.NewHTMLMessage(from, subject, body)
	msg.AddTo(email)

	msg.SetName(politeiaMailName)
	return b.cfg.SMTP.Send(msg)
}

// emailUpdateUserKeyVerificationLink emails the link with the verification token
// used for setting a new key pair if the email server is set up.
func (b *backend) emailUpdateUserKeyVerificationLink(email, publicKey, token string) error {
	if b.cfg.SMTP == nil {
		return nil
	}

	l, err := url.Parse(b.cfg.WebServerAddress + www.RouteVerifyUpdateUserKey)
	if err != nil {
		return err
	}
	q := l.Query()
	q.Set("verificationtoken", token)
	l.RawQuery = q.Encode()

	var buf bytes.Buffer
	tplData := updateUserKeyEmailTemplateData{
		Email:     email,
		PublicKey: publicKey,
		Link:      l.String(),
	}
	err = templateUpdateUserKeyEmail.Execute(&buf, &tplData)
	if err != nil {
		return err
	}
	from := "noreply@decred.org"
	subject := "Verify Your New Identity"
	body := buf.String()

	msg := goemail.NewHTMLMessage(from, subject, body)
	msg.AddTo(email)

	msg.SetName(politeiaMailName)
	return b.cfg.SMTP.Send(msg)
}

// makeRequest makes an http request to the method and route provided, serializing
// the provided object as the request body.
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

	req, err := http.NewRequest(method, fullRoute, bytes.NewReader(requestBody))
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

func (b *backend) validateUsername(username string) error {
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
		return www.UserError{
			ErrorCode: www.ErrorStatusDuplicateUsername,
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

	// Check for at least 1 markdown file with a non-emtpy payload.
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

func (b *backend) CreateLoginReply(user *database.User) *www.LoginReply {
	activeIdentity, ok := database.ActiveIdentityString(user.Identities)
	if !ok {
		activeIdentity = ""
	}

	reply := www.LoginReply{
		IsAdmin:   user.Admin,
		UserID:    strconv.FormatUint(user.ID, 10),
		Email:     user.Email,
		Username:  user.Username,
		PublicKey: activeIdentity,
	}

	if user.NewUserPaywallTx == "" {
		reply.PaywallAddress = user.NewUserPaywallAddress
		reply.PaywallAmount = user.NewUserPaywallAmount
		reply.PaywallTxNotBefore = user.NewUserPaywallTxNotBefore
	}

	return &reply
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
		b.Unlock()
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
		// Validate the username.
		err = b.validateUsername(u.Username)
		if err != nil {
			return nil, err
		}

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
			Username:       u.Username,
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

		// Get user that we just inserted so we can use their numerical user
		// ID (N) to derive the Nth paywall address from the paywall extended
		// public key.
		user, err := b.db.UserGet(u.Email)
		if err != nil {
			return nil, fmt.Errorf("Unable to retrieve account info for %v: %v",
				u.Email, err)
		}

		// Associate the user id with the new public key.
		b.setUserPubkeyAssociaton(user, u.PublicKey)

		// Derive a paywall address for this user if the paywall is enabled.
		paywallAddress := ""
		paywallAmount := uint64(0)
		if b.cfg.PaywallAmount != 0 && b.cfg.PaywallXpub != "" {
			paywallAddress, err = util.DerivePaywallAddress(b.params,
				b.cfg.PaywallXpub, uint32(user.ID))
			if err != nil {
				return nil, fmt.Errorf("Unable to derive paywall address #%v "+
					"for %v: %v", uint32(user.ID), u.Email, err)
			}
			paywallAmount = b.cfg.PaywallAmount
		}

		txNotBeforeTimestamp := time.Now().Unix()

		reply.PaywallAddress = paywallAddress
		reply.PaywallAmount = paywallAmount
		reply.PaywallTxNotBefore = txNotBeforeTimestamp

		user.NewUserPaywallAddress = paywallAddress
		user.NewUserPaywallAmount = paywallAmount
		user.NewUserPaywallTxNotBefore = txNotBeforeTimestamp

		err = b.db.UserUpdate(*user)
		if err != nil {
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

// ProcessUpdateUserKey sets a verification token and expiry to allow the user to
// update his key pair; the token must be verified before it expires. If the
// token is already set and is expired, it generates a new one.
func (b *backend) ProcessUpdateUserKey(user *database.User, u www.UpdateUserKey) (*www.UpdateUserKeyReply, error) {
	var reply www.UpdateUserKeyReply
	var token []byte
	var expiry int64

	// Ensure we have a proper pubkey.
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

	// Check if the verification token hasn't expired yet.
	if user.UpdateKeyVerificationToken != nil {
		currentTime := time.Now().Unix()
		if currentTime < user.UpdateKeyVerificationExpiry {
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
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenInvalid,
		}
	}

	// Check that the verification token matches.
	if !bytes.Equal(token, user.UpdateKeyVerificationToken) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenInvalid,
		}
	}

	// Check that the token hasn't expired.
	if currentTime := time.Now().Unix(); currentTime > user.UpdateKeyVerificationExpiry {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenExpired,
		}
	}

	// Check signature
	sig, err := util.ConvertSignature(vu.Signature)
	if err != nil {
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

	return b.CreateLoginReply(user), nil
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

	// Validate the new username.
	err = b.validateUsername(cu.NewUsername)
	if err != nil {
		return nil, err
	}

	// Add the updated user information to the db.
	user.Username = cu.NewUsername
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
			StatusMap: map[www.PropStatusT]bool{
				www.PropStatusPublic: true,
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
			StatusMap: map[www.PropStatusT]bool{
				www.PropStatusNotReviewed: true,
				www.PropStatusCensored:    true,
			},
		}),
	}
}

// ProcessNewProposal tries to submit a new proposal to politeiad.
func (b *backend) ProcessNewProposal(np www.NewProposal, user *database.User) (*www.NewProposalReply, error) {
	log.Tracef("ProcessNewProposal")

	if !b.VerifyUserPaid(user) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusUserNotPaid,
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
		b.Lock()
		err = b.newInventoryRecord(pd.Record{
			Status:           pd.RecordStatusNotReviewed,
			Timestamp:        ts,
			CensorshipRecord: pdReply.CensorshipRecord,
			Metadata:         n.Metadata,
			Files:            n.Files,
		})
		if err != nil {
			return nil, err
		}
		b.Unlock()
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
		b.Lock()
		b.newInventoryRecord(pd.Record{
			Status:           pd.RecordStatusNotReviewed,
			Timestamp:        ts,
			CensorshipRecord: pdReply.CensorshipRecord,
			Metadata:         n.Metadata,
			Files:            n.Files,
		})
		b.Unlock()
	}

	reply.CensorshipRecord = convertPropCensorFromPD(pdReply.CensorshipRecord)
	return &reply, nil
}

// ProcessSetProposalStatus changes the status of an existing proposal
// from unreviewed to either published or censored.
func (b *backend) ProcessSetProposalStatus(sps www.SetProposalStatus, user *database.User) (*www.SetProposalStatusReply, error) {
	err := checkPublicKeyAndSignature(user, sps.PublicKey, sps.Signature,
		sps.Token, strconv.FormatUint(uint64(sps.ProposalStatus), 10))
	if err != nil {
		return nil, err
	}

	// Create change record
	newStatus := convertPropStatusFromWWW(sps.ProposalStatus)
	r := MDStreamChanges{
		Timestamp: time.Now().Unix(),
		NewStatus: newStatus,
	}

	blob, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}

	var reply www.SetProposalStatusReply
	var pdReply pd.SetUnvettedStatusReply
	if b.test {
		pdReply.Record.Status = convertPropStatusFromWWW(sps.ProposalStatus)
	} else {
		// XXX Expensive to lock but do it for now.
		// Lock is needed to prevent a race into this record and it
		// needs to be updated in the cache.
		b.Lock()
		defer b.Unlock()

		// When not in testnet, block admins
		// from changing the status of their own proposals
		if !b.cfg.TestNet {
			pr, err := b.getProposal(sps.Token)
			if err != nil {
				return nil, err
			}
			if pr.UserId == strconv.FormatUint(user.ID, 10) {
				return nil, v1.UserError{
					ErrorCode: v1.ErrorStatusReviewerAdminEqualsAuthor,
				}
			}
		}

		challenge, err := util.Random(pd.ChallengeSize)
		if err != nil {
			return nil, err
		}

		var ok bool
		r.AdminPubKey, ok = database.ActiveIdentityString(user.Identities)
		if !ok {
			return nil, fmt.Errorf("invalid admin identity: %v",
				user.ID)
		}

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

		err = json.Unmarshal(responseBody, &pdReply)
		if err != nil {
			return nil, fmt.Errorf("Could not unmarshal SetUnvettedStatusReply: %v",
				err)
		}

		// Verify the challenge.
		err = util.VerifyChallenge(b.cfg.Identity, challenge, pdReply.Response)
		if err != nil {
			return nil, err
		}

		// Update the inventory with the metadata changes.
		b.updateInventoryRecord(pdReply.Record)
	}

	// Return the reply.
	reply.Proposal = convertPropFromPD(pdReply.Record)

	return &reply, nil
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
	p, ok := b.inventory[propDetails.Token]
	if !ok {
		b.RUnlock()
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusProposalNotFound,
		}
	}
	b.RUnlock()
	cachedProposal := convertPropFromInventoryRecord(p, b.userPubkeys)

	var isVettedProposal bool
	var requestObject interface{}
	if cachedProposal.Status == www.PropStatusPublic {
		isVettedProposal = true
		requestObject = pd.GetVetted{
			Token:     propDetails.Token,
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
	// non-admins; only the proposal meta data (status, censorship data, etc)
	// should be publicly viewable.
	isUserAdmin := user != nil && user.Admin
	if !isVettedProposal && !isUserAdmin {
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

		if user != nil {
			authorId, err := strconv.ParseUint(cachedProposal.UserId, 10, 64)
			if err != nil {
				return nil, err
			}

			if user.ID == authorId {
				reply.Proposal.Name = cachedProposal.Name
			}
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

	reply.Proposal = convertPropFromInventoryRecord(&inventoryRecord{
		record:   fullRecord,
		changes:  p.changes,
		comments: p.comments,
	}, b.userPubkeys)
	reply.Proposal.Username = b.getUsernameById(reply.Proposal.UserId)
	return &reply, nil
}

// ProcessComment processes a submitted comment.  It ensures the proposal and
// the parent exists.  A parent ID of 0 indicates that it is a comment on the
// proposal whereas non-zero indicates that it is a reply to a comment.
func (b *backend) ProcessComment(c www.NewComment, user *database.User) (*www.NewCommentReply, error) {
	log.Debugf("ProcessComment: %v %v", c.Token, user.ID)

	// Pay up sucker!
	if !b.VerifyUserPaid(user) {
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
	ncrWWW := b.convertDecredNewCommentReplyToWWWNewCommentReply(*ncr)

	// Add comment to cache
	b.Lock()
	defer b.Unlock()

	b.inventory[ncrWWW.Comment.Token].comments[ncrWWW.Comment.CommentID] = ncrWWW.Comment

	return &ncrWWW, nil
}

// ProcessCommentGet returns all comments for a given proposal.
func (b *backend) ProcessCommentGet(token string) (*www.GetCommentsReply, error) {
	log.Debugf("ProcessCommentGet: %v", token)

	c, err := b.getComments(token)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// ProcessUserProposals returns the proposals for the given user.
func (b *backend) ProcessUserProposals(up *www.UserProposals, isCurrentUser, isAdminUser bool) (*www.UserProposalsReply, error) {
	return &www.UserProposalsReply{
		Proposals: b.getProposals(proposalsRequest{
			After:  up.After,
			Before: up.Before,
			UserId: up.UserId,
			StatusMap: map[www.PropStatusT]bool{
				www.PropStatusNotReviewed: isCurrentUser || isAdminUser,
				www.PropStatusCensored:    isCurrentUser || isAdminUser,
				www.PropStatusPublic:      true,
			},
		}),
	}, nil
}

func (b *backend) ProcessActiveVote() (*www.ActiveVoteReply, error) {
	log.Tracef("ProcessActiveVote")

	//  We need to determine best block height here and only return active
	//  votes.
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
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

	bestBlock, err := strconv.ParseUint(reply.Payload, 10, 64)
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
			Proposal:    convertPropFromPD(i.record),
			Vote:        i.votebits,
			VoteDetails: i.voting,
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

func (b *backend) ProcessStartVote(sv www.StartVote, user *database.User) (*www.StartVoteReply, error) {
	log.Tracef("ProcessStartVote %v", sv.Vote.Token)

	// XXX Verify user
	//err := checkPublicKeyAndSignature(user, sv.PublicKey, sv.Signature, sv.Token)
	//if err != nil {
	//	return nil, err
	//}

	// XXX validate vote bits

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

	// Look up token and ensure record is public and does not need to be
	// updated
	ir, err := b._getInventoryRecord(sv.Vote.Token)
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

	// We can get away with only updating the voting metadata in cache
	// XXX this is cheating a bit and we should add an api for this or toss the cache altogether
	vr, err := decredplugin.DecodeStartVoteReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}
	ir.voting = convertStartVoteReplyFromDecredplugin(*vr)
	ir.votebits = sv.Vote
	b.inventory[sv.Vote.Token] = &ir

	// return a copy
	rv := ir.voting
	return &rv, nil
}

func (b *backend) ProcessVoteResults(vr *www.VoteResults) (*www.VoteResultsReply, error) {
	log.Tracef("ProcessVoteResults")

	payload, err := decredplugin.EncodeVoteResults(convertVoteResultsFromWWW(*vr))
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
		CommandID: decredplugin.CmdProposalVotes + " " + vr.Token,
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
	wvrr := convertVoteResultsReplyFromDecredplugin(*vrr)
	return &wvrr, nil
}

// ProcessPolicy returns the details of Politeia's restrictions on file uploads.
func (b *backend) ProcessPolicy(p www.Policy) *www.PolicyReply {
	return &www.PolicyReply{
		MinPasswordLength:          www.PolicyMinPasswordLength,
		MinUsernameLength:          www.PolicyMinUsernameLength,
		MaxUsernameLength:          www.PolicyMaxUsernameLength,
		UsernameSupportedChars:     www.PolicyUsernameSupportedChars,
		ProposalListPageSize:       www.ProposalListPageSize,
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
		db:          db,
		cfg:         cfg,
		userPubkeys: make(map[string]string),
	}

	// Setup pubkey-userid map
	err = b.initUserPubkeys()
	if err != nil {
		return nil, err
	}

	return b, nil
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
