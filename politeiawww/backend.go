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
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/dajohi/goemail"
	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrtime/merkle"
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
	mdStreamGeneral  = 0 // General information for this proposal
	mdStreamComments = 1 // Comments
	mdStreamChanges  = 2 // Changes to record
)

type MDStreamChanges struct {
	AdminPubKey string           // Identity of the administrator
	NewStatus   pd.RecordStatusT // NewStatus
	Timestamp   int64            // Timestamp of the change
}

// politeiawww backend construct
type backend struct {
	sync.RWMutex // lock for inventory and comments

	db                 database.Database
	cfg                *config
	params             *chaincfg.Params
	commentJournalDir  string
	commentJournalFile string

	// These properties are only used for testing.
	test                   bool
	verificationExpiryTime time.Duration

	// Following entries require locks
	comments  map[string]map[uint64]BackendComment // [token][parent]comment
	commentID uint64                               // current comment id

	// When inventory is set or modified inventoryVersion MUST be
	// incremented.  When inventory changes the caller MUST initialize the
	// comments map for the associated censorship token.
	inventory        []www.ProposalRecord // current inventory
	inventoryVersion uint                 // inventory version
}

const BackendProposalMetadataVersion = 1

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
	subject := "Politeia Registration - Verify Your Email"
	body := buf.String()

	msg := goemail.NewHTMLMessage(from, subject, body)
	msg.AddTo(email)

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
	subject := "Politeia - Reset Your Password"
	body := buf.String()

	msg := goemail.NewHTMLMessage(from, subject, body)
	msg.AddTo(email)

	return b.cfg.SMTP.Send(msg)
}

// makeRequest makes an http request to the method and route provided, serializing
// the provided object as the request body.
func (b *backend) makeRequest(method string, route string, v interface{}) ([]byte, error) {
	var requestBody []byte
	if v != nil {
		var err error
		requestBody, err = json.Marshal(v)
		if err != nil {
			return nil, err
		}
	}

	fullRoute := b.cfg.RPCHost + route

	c, err := util.NewClient(false, b.cfg.RPCCert)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(method, fullRoute, bytes.NewReader(requestBody))
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

func (b *backend) validatePassword(password string) error {
	if len(password) < www.PolicyPasswordMinChars {
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

	// Verify user used correct key
	id, ok := database.ActiveIdentity(user.Identities)
	if !ok {
		return www.UserError{
			ErrorCode: www.ErrorStatusNoPublicKey,
		}
	}
	if hex.EncodeToString(id[:]) != np.PublicKey {
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidSigningKey,
		}
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
			ErrorContext: []string{util.CreateProposalTitleRegex()},
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
// must be called WITHOUT the lock held.
func (b *backend) loadInventory() (*pd.InventoryReply, error) {
	if !b.test {
		return b.remoteInventory()
	}

	// Split the existing inventory into vetted and unvetted.
	vetted := make([]www.ProposalRecord, 0)
	unvetted := make([]www.ProposalRecord, 0)

	b.Lock()
	defer b.Unlock()
	for _, v := range b.inventory {
		if v.Status == www.PropStatusPublic {
			vetted = append(vetted, v)
		} else {
			unvetted = append(unvetted, v)
		}
	}

	return &pd.InventoryReply{
		Vetted:   convertPropsFromWWW(vetted),
		Branches: convertPropsFromWWW(unvetted),
	}, nil
}

func (b *backend) getProposals(after, before string, statusMap map[www.PropStatusT]bool) []www.ProposalRecord {
	b.RLock()
	defer b.RUnlock()

	// pageStarted stores whether or not it's okay to start adding
	// proposals to the array. If the after or before parameter is
	// supplied, we must find the beginning (or end) of the page first.
	pageStarted := (after == "" && before == "")
	beforeIdx := -1
	proposals := make([]www.ProposalRecord, 0)

	// Iterate in reverse order because they're sorted by oldest timestamp
	// first.
	for i := len(b.inventory) - 1; i >= 0; i-- {
		proposal := b.inventory[i]
		if _, ok := statusMap[proposal.Status]; ok {
			if pageStarted {
				proposals = append(proposals, proposal)
				if len(proposals) >= www.ProposalListPageSize {
					break
				}
			} else if after != "" {
				// The beginning of the page has been found, so
				// the next public proposal is added.
				pageStarted = proposal.CensorshipRecord.Token == after
			} else if before != "" {
				// The end of the page has been found, so we'll
				// have to iterate in the other direction to
				// add the proposals; save the current index.
				if proposal.CensorshipRecord.Token == before {
					beforeIdx = i
					break
				}
			}
		}
	}

	// If beforeIdx is set, the caller is asking for vetted proposals whose
	// last result is before the provided proposal.
	if beforeIdx >= 0 {
		for _, proposal := range b.inventory[beforeIdx+1:] {
			if _, ok := statusMap[proposal.Status]; ok {
				// The iteration direction is oldest -> newest,
				// so proposals are prepended to the array so
				// the result will be newest -> oldest.
				proposals = append([]www.ProposalRecord{proposal},
					proposals...)
				if len(proposals) >= www.ProposalListPageSize {
					break
				}
			}
		}
	}

	return proposals
}

// LoadInventory fetches the entire inventory of proposals from politeiad and
// caches it, sorted by most recent timestamp.
func (b *backend) LoadInventory() error {
	// This function is a little hard to read but we must make sure that
	// the inventory has not changed since we tried to load it.  We can't
	// lock it for the duration because the RPC call is potentially very
	// slow.
	b.Lock()
	if b.inventory != nil {
		b.Unlock()
		return nil
	}
	currentInventory := b.inventoryVersion
	b.Unlock()

	// get remote inventory
	for {
		// Fetch remote inventory.
		inv, err := b.loadInventory()
		if err != nil {
			return fmt.Errorf("LoadInventory: %v", err)
		}

		b.Lock()
		// Restart operation if inventory changed from underneath us.
		if currentInventory != b.inventoryVersion {
			currentInventory = b.inventoryVersion
			b.Unlock()
			log.Debugf("LoadInventory: restarting reload")
			continue
		}

		b.inventory = make([]www.ProposalRecord, 0,
			len(inv.Vetted)+len(inv.Branches))
		for _, vv := range append(inv.Vetted, inv.Branches...) {
			v := convertPropFromPD(vv)
			// Initialize comment map for this proposal.
			b.initComment(v.CensorshipRecord.Token)
			len := len(b.inventory)
			if len == 0 {
				b.inventory = append(b.inventory, v)
				continue
			}
			idx := sort.Search(len, func(i int) bool {
				return v.Timestamp < b.inventory[i].Timestamp
			})

			// Insert the proposal at idx.
			b.inventory = append(b.inventory[:idx],
				append([]www.ProposalRecord{v},
					b.inventory[idx:]...)...)
		}
		b.inventoryVersion++
		b.Unlock()

		log.Infof("Adding %v vetted, %v unvetted proposals to the cache",
			len(inv.Vetted), len(inv.Branches))

		break
	}

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

		// Get user that we just inserted so we can use their numerical user
		// ID (N) to derive the Nth paywall address from the paywall extended
		// public key.
		user, err := b.db.UserGet(u.Email)
		if err != nil {
			return nil, fmt.Errorf("Unable to retrieve account info for %v: %v",
				u.Email, err)
		}

		// Derive a paywall address for this user if the paywall is enabled.
		paywallAddress := ""
		paywallAmount := float64(0)
		if b.cfg.PaywallXpub != "" {
			paywallAddress, err = util.DerivePaywallAddress(b.params,
				b.cfg.PaywallXpub, uint32(user.ID))
			if err != nil {
				return nil, fmt.Errorf("Unable to derive paywall address #%v "+
					"for %v: %v", uint32(user.ID), u.Email, err)
			}
			paywallAmount = b.cfg.PaywallAmount
		}

		reply.PaywallAddress = paywallAddress
		reply.PaywallAmount = paywallAmount
		user.NewUserPaywallAddress = paywallAddress
		user.NewUserPaywallAmount = paywallAmount
		user.NewUserPaywallTxNotBefore = time.Now().Unix()

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

// ProcessAllVetted returns an array of vetted proposals. The maximum number
// of proposals returned is dictated by www.ProposalListPageSize.
func (b *backend) ProcessAllVetted(v www.GetAllVetted) *www.GetAllVettedReply {
	return &www.GetAllVettedReply{
		Proposals: b.getProposals(v.After, v.Before,
			map[www.PropStatusT]bool{
				www.PropStatusPublic: true,
			}),
	}
}

// ProcessAllUnvetted returns an array of all unvetted proposals in reverse order,
// because they're sorted by oldest timestamp first.
func (b *backend) ProcessAllUnvetted(u www.GetAllUnvetted) *www.GetAllUnvettedReply {
	return &www.GetAllUnvettedReply{
		Proposals: b.getProposals(u.After, u.Before,
			map[www.PropStatusT]bool{
				www.PropStatusNotReviewed: true,
				www.PropStatusCensored:    true,
			}),
	}
}

// ProcessNewProposal tries to submit a new proposal to politeiad.
func (b *backend) ProcessNewProposal(np www.NewProposal, user *database.User) (*www.NewProposalReply, error) {
	log.Tracef("ProcessNewProposal")

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
		tokenBytes, err := util.Random(16)
		if err != nil {
			return nil, err
		}

		pdReply.CensorshipRecord = pd.CensorshipRecord{
			Token: hex.EncodeToString(tokenBytes),
		}

		// Add the new proposal to the cache.
		b.Lock()
		b.inventory = append(b.inventory, www.ProposalRecord{
			Name:             name,
			Status:           www.PropStatusNotReviewed,
			Timestamp:        ts,
			PublicKey:        np.PublicKey,
			Signature:        np.Signature,
			Files:            np.Files,
			CensorshipRecord: convertPropCensorFromPD(pdReply.CensorshipRecord),
		})
		b.inventoryVersion++
		b.initComment(pdReply.CensorshipRecord.Token)
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

		// Add the new proposal to the cache.
		r := www.ProposalRecord{
			Name:             name,
			Status:           www.PropStatusNotReviewed,
			Timestamp:        ts,
			PublicKey:        np.PublicKey,
			Signature:        np.Signature,
			Files:            make([]www.File, 0),
			CensorshipRecord: convertPropCensorFromPD(pdReply.CensorshipRecord),
		}
		b.Lock()
		b.inventory = append(b.inventory, r)
		b.inventoryVersion++
		b.initComment(pdReply.CensorshipRecord.Token)
		b.Unlock()
	}

	reply.CensorshipRecord = convertPropCensorFromPD(pdReply.CensorshipRecord)
	return &reply, nil
}

// ProcessSetProposalStatus changes the status of an existing proposal
// from unreviewed to either published or censored.
func (b *backend) ProcessSetProposalStatus(sps www.SetProposalStatus, user *database.User) (*www.SetProposalStatusReply, error) {
	// Validate signature
	err := checkSig(user, sps.Signature, sps.Token,
		strconv.FormatUint(uint64(sps.ProposalStatus), 10))
	if err != nil {
		return nil, err
	}

	var reply www.SetProposalStatusReply
	var pdReply pd.SetUnvettedStatusReply
	if b.test {
		pdReply.Status = convertPropStatusFromWWW(sps.ProposalStatus)
	} else {
		challenge, err := util.Random(pd.ChallengeSize)
		if err != nil {
			return nil, err
		}

		// Create chnage record
		newStatus := convertPropStatusFromWWW(sps.ProposalStatus)
		r := MDStreamChanges{
			Timestamp: time.Now().Unix(),
			NewStatus: newStatus,
		}
		if ai, ok := database.ActiveIdentityString(user.Identities); !ok {
			return nil, fmt.Errorf("invalid admin identity: %v",
				user.ID)
		} else {
			r.AdminPubKey = ai
		}
		blob, err := json.Marshal(r)
		if err != nil {
			return nil, err
		}

		sus := pd.SetUnvettedStatus{
			Token:     sps.Token,
			Status:    newStatus,
			Challenge: hex.EncodeToString(challenge),
			MDOverwrite: []pd.MetadataStream{
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
	}

	// Update the cached proposal with the new status and return the reply.
	b.Lock()
	defer b.Unlock()
	for k, v := range b.inventory {
		if v.CensorshipRecord.Token == sps.Token {
			s := convertPropStatusFromPD(pdReply.Status)
			b.inventory[k].Status = s
			reply.ProposalStatus = s
			return &reply, nil
		}
	}

	return nil, www.UserError{
		ErrorCode: www.ErrorStatusProposalNotFound,
	}
}

// ProcessProposalDetails tries to fetch the full details of a proposal from politeiad.
func (b *backend) ProcessProposalDetails(propDetails www.ProposalsDetails, isUserAdmin bool) (*www.ProposalDetailsReply, error) {
	var reply www.ProposalDetailsReply
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	var cachedProposal *www.ProposalRecord
	b.RLock()
	for _, v := range b.inventory {
		if v.CensorshipRecord.Token == propDetails.Token {
			cachedProposal = &v
			break
		}
	}
	b.RUnlock()
	if cachedProposal == nil {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusProposalNotFound,
		}
	}

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
		reply.Proposal = *cachedProposal
		return &reply, nil
	}

	// The title and files for unvetted proposals should not be viewable by
	// non-admins; only the proposal meta data (status, censorship data, etc)
	// should be publicly viewable.
	if !isVettedProposal && !isUserAdmin {
		reply.Proposal = www.ProposalRecord{
			Status:           cachedProposal.Status,
			Timestamp:        cachedProposal.Timestamp,
			PublicKey:        cachedProposal.PublicKey,
			Signature:        cachedProposal.Signature,
			CensorshipRecord: cachedProposal.CensorshipRecord,
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
	var proposal pd.Record
	if isVettedProposal {
		var pdReply pd.GetVettedReply
		err = json.Unmarshal(responseBody, &pdReply)
		if err != nil {
			return nil, fmt.Errorf("Could not unmarshal "+
				"GetVettedReply: %v", err)
		}

		response = pdReply.Response
		proposal = pdReply.Record
	} else {
		var pdReply pd.GetUnvettedReply
		err = json.Unmarshal(responseBody, &pdReply)
		if err != nil {
			return nil, fmt.Errorf("Could not unmarshal "+
				"GetUnvettedReply: %v", err)
		}

		response = pdReply.Response
		proposal = pdReply.Record
	}

	// Verify the challenge.
	err = util.VerifyChallenge(b.cfg.Identity, challenge, response)
	if err != nil {
		return nil, err
	}

	reply.Proposal = convertPropFromPD(proposal)
	return &reply, nil
}

// ProcessComment processes a submitted comment.  It ensures the proposal and
// the parent exists.  A parent ID of 0 indicates that it is a comment on the
// proposal whereas non-zero indicates that it is a reply to a comment.
func (b *backend) ProcessComment(c www.NewComment, user *database.User) (*www.NewCommentReply, error) {
	log.Debugf("ProcessComment: %v %v", c.Token, user.ID)

	// Verify signature
	err := checkSig(user, c.Signature, c.Token, c.ParentID, c.Comment)
	if err != nil {
		return nil, err
	}

	b.Lock()
	defer b.Unlock()
	m, ok := b.comments[c.Token]
	if !ok {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusProposalNotFound,
		}
	}

	// See if we are commenting on a comment, yo dawg.
	if c.ParentID == "" {
		// "" means top level comment; we need it to be "0" for the
		// underlying code to understand that.
		c.ParentID = "0"
	}
	pid, err := strconv.ParseUint(c.ParentID, 10, 64)
	if err != nil {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusCommentNotFound,
		}
	}
	if pid != 0 {
		_, ok = m[pid]
		if !ok {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusCommentNotFound,
			}
		}
	}

	return b.addComment(c, user.ID)
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

// ProcessPolicy returns the details of Politeia's restrictions on file uploads.
func (b *backend) ProcessPolicy(p www.Policy) *www.PolicyReply {
	return &www.PolicyReply{
		PasswordMinChars:     www.PolicyPasswordMinChars,
		ProposalListPageSize: www.ProposalListPageSize,
		MaxImages:            www.PolicyMaxImages,
		MaxImageSize:         www.PolicyMaxImageSize,
		MaxMDs:               www.PolicyMaxMDs,
		MaxMDSize:            www.PolicyMaxMDSize,
		ValidMIMETypes:       mime.ValidMimeTypes(),
		MaxNameLength:        www.PolicyMaxProposalNameLength,
		MinNameLength:        www.PolicyMinProposalNameLength,
		SupportedCharacters:  www.PolicyProposalNameSupportedCharacters,
		MaxCommentLength:     www.PolicyMaxCommentLength,
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
		db:       db,
		cfg:      cfg,
		comments: make(map[string]map[uint64]BackendComment),
		commentJournalDir: filepath.Join(cfg.DataDir,
			defaultCommentJournalDir),
		commentID: 1, // Replay will set this value
	}

	// Setup comments
	os.MkdirAll(b.commentJournalDir, 0744)
	err = b.replayCommentJournals()
	if err != nil {
		return nil, err
	}

	// Flush comments
	err = b.flushCommentJournals()
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
