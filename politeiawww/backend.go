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
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/dajohi/goemail"
	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/mime"
	www "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/database"
	"github.com/decred/politeia/politeiawww/database/localdb"
	"github.com/decred/politeia/util"
	"github.com/kennygrant/sanitize"
)

// politeiawww backend construct
type backend struct {
	db        database.Database
	cfg       *config
	inventory []www.ProposalRecord

	// These properties are only used for testing.
	test                   bool
	verificationExpiryTime time.Duration
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

// emailVerificationLink emails the link with the verification token
// if the email server is set up.
func (b *backend) emailVerificationLink(email, token string) error {
	if b.cfg.SMTP == nil {
		return nil
	}

	l, err := url.Parse(b.cfg.WebServerAddress + www.RouteVerifyNewUser)
	if err != nil {
		return err
	}
	q := l.Query()
	q.Set("email", email)
	q.Set("token", token)
	l.RawQuery = q.Encode()

	var buf bytes.Buffer
	tplData := emailTemplateData{
		Email: email,
		Link:  l.String(),
	}
	err = templateEmail.Execute(&buf, &tplData)
	if err != nil {
		return err
	}
	from := "noreply@decred.org"
	subject := "Politeia Registration - Verify Your Email"
	body := buf.String()

	msg := goemail.NewHTMLMessage(from, subject, body)
	msg.AddTo(email)

	if err := b.cfg.SMTP.Send(msg); err != nil {
		return err
	}

	return nil
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
		e, err := util.GetErrorFromJSON(r.Body)
		if err != nil {
			return nil, fmt.Errorf("%v", r.Status)
		}
		return nil, fmt.Errorf("%v: %v", r.Status, e)
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
		return nil, fmt.Errorf("Could not unmarshal InventoryReply: %v",
			err)
	}

	err = util.VerifyChallenge(b.cfg.Identity, challenge, ir.Response)
	if err != nil {
		return nil, err
	}

	return &ir, nil
}

func (b *backend) validateProposal(np www.NewProposal) (www.StatusT, error) {
	// Check for a non-empty name.
	if np.Name == "" {
		return www.StatusProposalMissingName, nil
	}

	// Check for at least 1 markdown file with a non-emtpy payload.
	if len(np.Files) == 0 || np.Files[0].Payload == "" {
		return www.StatusProposalMissingDescription, nil
	}

	// Check that the file number policy is followed.
	var numMDs, numImages uint = 0, 0
	var mdExceedsMaxSize, imageExceedsMaxSize bool = false, false
	for _, v := range np.Files {
		if strings.HasPrefix(v.MIME, "image/") {
			numImages++
			data, err := base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				return www.StatusInvalid, err
			}
			if len(data) > www.PolicyMaxImageSize {
				imageExceedsMaxSize = true
			}
		} else {
			numMDs++
			data, err := base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				return www.StatusInvalid, err
			}
			if len(data) > www.PolicyMaxMDSize {
				mdExceedsMaxSize = true
			}
		}
	}

	if numMDs > www.PolicyMaxMDs {
		return www.StatusMaxMDsExceededPolicy, nil
	}

	if numImages > www.PolicyMaxImages {
		return www.StatusMaxImagesExceededPolicy, nil
	}

	if mdExceedsMaxSize {
		return www.StatusMaxMDSizeExceededPolicy, nil
	}

	if imageExceedsMaxSize {
		return www.StatusMaxImageSizeExceededPolicy, nil
	}

	return www.StatusSuccess, nil
}

// LoadInventory fetches the entire inventory of proposals from politeiad
// and caches it, sorted by most recent timestamp.
func (b *backend) LoadInventory() error {
	var inv *pd.InventoryReply
	if b.test {
		// Split the existing inventory into vetted and unvetted.
		vetted := make([]www.ProposalRecord, 0, 0)
		unvetted := make([]www.ProposalRecord, 0, 0)

		for _, v := range b.inventory {
			if v.Status == www.PropStatusPublic {
				vetted = append(vetted, v)
			} else {
				unvetted = append(unvetted, v)
			}
		}

		inv = &pd.InventoryReply{
			Vetted:   convertPropsFromWWW(vetted),
			Branches: convertPropsFromWWW(unvetted),
		}
	} else {
		// Fetch remote inventory.
		var err error
		inv, err = b.remoteInventory()
		if err != nil {
			return fmt.Errorf("LoadInventory: %v", err)
		}

		log.Infof("Adding %v vetted, %v unvetted proposals to the cache",
			len(inv.Vetted), len(inv.Branches))
	}

	b.inventory = make([]www.ProposalRecord, 0, len(inv.Vetted)+len(inv.Branches))
	for _, vv := range append(inv.Vetted, inv.Branches...) {
		v := convertPropFromPD(vv)
		len := len(b.inventory)
		if len == 0 {
			b.inventory = append(b.inventory, v)
		} else {
			idx := sort.Search(len, func(i int) bool {
				return v.Timestamp < b.inventory[i].Timestamp
			})

			b.inventory = append(b.inventory[:idx],
				append([]www.ProposalRecord{v},
					b.inventory[idx:]...)...)
		}
	}

	return nil
}

// ProcessNewUser creates a new user in the db if it doesn't already
// exist and sets a verification token and expiry; the token must be
// verified before it expires. If the user already exists in the db
// and its token is expired, it generates a new one.
//
// Note that this function always returns a NewUserReply.  The caller shally
// verify error and determine how to return this information upstream.
func (b *backend) ProcessNewUser(u www.NewUser) (*www.NewUserReply, error) {
	var token []byte
	var expiry int64

	// XXX this function really needs to be cleaned up.
	// XXX We should create a sinlge reply struct that get's returned
	// instead of many.

	// Check if the user already exists.
	if user, err := b.db.UserGet(u.Email); err == nil {
		// Check if the user is already verified.
		if user.VerificationToken == nil {
			reply := www.NewUserReply{
				ErrorCode: www.StatusSuccess,
			}
			return &reply, nil
		}

		// Check if the verification token hasn't expired yet.
		if currentTime := time.Now().Unix(); currentTime < user.VerificationExpiry {
			reply := www.NewUserReply{
				ErrorCode: www.StatusSuccess,
			}
			return &reply, nil
		}

		// Generate a new verification token and expiry.
		token, expiry, err = b.generateVerificationTokenAndExpiry()
		if err != nil {
			reply := www.NewUserReply{
				ErrorCode: www.StatusInvalid,
			}
			return &reply, err
		}

		// Add the updated user information to the db.
		user.VerificationToken = token
		user.VerificationExpiry = expiry
		err = b.db.UserUpdate(*user)
		if err != nil {
			reply := www.NewUserReply{
				ErrorCode: www.StatusInvalid,
			}
			return &reply, err
		}
	} else {
		// Hash the user's password.
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.Password),
			bcrypt.DefaultCost)
		if err != nil {
			reply := www.NewUserReply{
				ErrorCode: www.StatusInvalid,
			}
			return &reply, err
		}

		// Generate the verification token and expiry.
		token, expiry, err = b.generateVerificationTokenAndExpiry()
		if err != nil {
			reply := www.NewUserReply{
				ErrorCode: www.StatusInvalid,
			}
			return &reply, err
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
			if err == database.ErrInvalidEmail {
				reply := www.NewUserReply{
					ErrorCode: www.StatusMalformedEmail,
				}
				return &reply, nil
			}

			reply := www.NewUserReply{
				ErrorCode: www.StatusInvalid,
			}
			return &reply, err
		}
	}

	if !b.test {
		// This is confitional on email server being setup.
		err := b.emailVerificationLink(u.Email, hex.EncodeToString(token))
		if err != nil {
			reply := www.NewUserReply{
				ErrorCode: www.StatusInvalid,
			}
			return &reply, err
		}
	}

	// Reply with an empty response, which indicates success.
	reply := www.NewUserReply{
		ErrorCode: www.StatusSuccess,
	}

	// We only set the token if email verification is disabled.
	if b.cfg.SMTP == nil {
		reply.VerificationToken = hex.EncodeToString(token)
	}
	return &reply, nil
}

// ProcessVerifyNewUser verifies the token generated for a recently created user.
// It ensures that the token matches with the input and that the token hasn't expired.
func (b *backend) ProcessVerifyNewUser(u www.VerifyNewUser) (www.StatusT, error) {
	// Check that the user already exists.
	user, err := b.db.UserGet(u.Email)
	if err != nil {
		if err == database.ErrUserNotFound {
			return www.StatusVerificationTokenInvalid, nil
		}
		return www.StatusSuccess, err
	}

	// Decode the verification token.
	token, err := hex.DecodeString(u.VerificationToken)
	if err != nil {
		return www.StatusVerificationTokenInvalid, err
	}

	// Check that the verification token matches.
	if !bytes.Equal(token, user.VerificationToken) {
		return www.StatusVerificationTokenInvalid, nil
	}

	// Check that the token hasn't expired.
	if currentTime := time.Now().Unix(); currentTime > user.VerificationExpiry {
		return www.StatusVerificationTokenExpired, nil
	}

	// Clear out the verification token fields in the db.
	user.VerificationToken = nil
	user.VerificationExpiry = 0
	err = b.db.UserUpdate(*user)
	if err != nil {
		return www.StatusInvalid, err
	}

	return www.StatusSuccess, nil
}

// ProcessLogin checks that a user exists, is verified, and has
// the correct password.
func (b *backend) ProcessLogin(l www.Login) (*www.LoginReply, error) {
	// Get user from db.
	user, err := b.db.UserGet(l.Email)
	if err != nil {
		if err == database.ErrUserNotFound {
			reply := www.LoginReply{
				ErrorCode: www.StatusInvalidEmailOrPassword,
			}
			return &reply, nil
		}
		return nil, err
	}

	// Check that the user is verified.
	if user.VerificationToken != nil {
		reply := www.LoginReply{
			ErrorCode: www.StatusInvalidEmailOrPassword,
		}
		return &reply, nil
	}

	// Check the user's password.
	err = bcrypt.CompareHashAndPassword(user.HashedPassword,
		[]byte(l.Password))
	if err != nil {
		reply := www.LoginReply{
			ErrorCode: www.StatusInvalidEmailOrPassword,
		}
		return &reply, nil
	}

	reply := www.LoginReply{
		IsAdmin:   user.Admin,
		ErrorCode: www.StatusSuccess,
	}
	return &reply, nil
}

// ProcessAllVetted returns an array of all vetted proposals in reverse order,
// because they're sorted by oldest timestamp first.
func (b *backend) ProcessAllVetted() *www.GetAllVettedReply {
	proposals := make([]www.ProposalRecord, 0, 0)
	for i := len(b.inventory) - 1; i >= 0; i-- {
		if b.inventory[i].Status == www.PropStatusPublic {
			proposals = append(proposals, b.inventory[i])
		}
	}

	vr := www.GetAllVettedReply{
		Proposals: proposals,
		ErrorCode: www.StatusSuccess,
	}
	return &vr
}

// ProcessAllUnvetted returns an array of all unvetted proposals in reverse order,
// because they're sorted by oldest timestamp first.
func (b *backend) ProcessAllUnvetted() *www.GetAllUnvettedReply {
	proposals := make([]www.ProposalRecord, 0, 0)
	for i := len(b.inventory) - 1; i >= 0; i-- {
		if b.inventory[i].Status == www.PropStatusNotReviewed {
			proposals = append(proposals, b.inventory[i])
		}
	}

	ur := www.GetAllUnvettedReply{
		Proposals: proposals,
		ErrorCode: www.StatusSuccess,
	}
	return &ur
}

// ProcessNewProposal tries to submit a new proposal to politeiad.
func (b *backend) ProcessNewProposal(np www.NewProposal) (*www.NewProposalReply, error) {
	status, err := b.validateProposal(np)
	if err != nil {
		return nil, err
	}
	if status != www.StatusSuccess {
		reply := www.NewProposalReply{
			ErrorCode: status,
		}
		return &reply, nil
	}

	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	n := pd.New{
		Name:      sanitize.Name(np.Name),
		Challenge: hex.EncodeToString(challenge),
		Files:     convertPropFilesFromWWW(np.Files),
	}

	for k, f := range n.Files {
		decodedPayload, err := base64.StdEncoding.DecodeString(f.Payload)
		if err != nil {
			return nil, err
		}

		// Calculate the digest for each file.
		h := sha256.New()
		h.Write(decodedPayload)
		n.Files[k].Digest = hex.EncodeToString(h.Sum(nil))
	}

	var reply pd.NewReply
	if b.test {
		tokenBytes, err := util.Random(16)
		if err != nil {
			return nil, err
		}

		reply = pd.NewReply{
			Timestamp: time.Now().Unix(),
			CensorshipRecord: pd.CensorshipRecord{
				Token: hex.EncodeToString(tokenBytes),
			},
		}

		// Add the new proposal to the cache.
		b.inventory = append(b.inventory, www.ProposalRecord{
			Name:             np.Name,
			Status:           www.PropStatusNotReviewed,
			Timestamp:        reply.Timestamp,
			Files:            np.Files,
			CensorshipRecord: convertPropCensorFromPD(reply.CensorshipRecord),
		})
	} else {
		responseBody, err := b.makeRequest(http.MethodPost, pd.NewRoute, n)
		if err != nil {
			return nil, err
		}

		fmt.Printf("Submitted proposal name: %v\n", n.Name)
		for k, f := range n.Files {
			fmt.Printf("%02v: %v %v\n", k, f.Name, f.Digest)
		}

		err = json.Unmarshal(responseBody, &reply)
		if err != nil {
			return nil, fmt.Errorf("Could not unmarshal NewProposalReply: %v", err)
		}

		// Verify the challenge.
		err = util.VerifyChallenge(b.cfg.Identity, challenge, reply.Response)
		if err != nil {
			return nil, err
		}

		// Add the new proposal to the cache.
		b.inventory = append(b.inventory, www.ProposalRecord{
			Name:             np.Name,
			Status:           www.PropStatusNotReviewed,
			Timestamp:        reply.Timestamp,
			Files:            make([]www.File, 0, 0),
			CensorshipRecord: convertPropCensorFromPD(reply.CensorshipRecord),
		})
	}

	npr := www.NewProposalReply{
		CensorshipRecord: convertPropCensorFromPD(reply.CensorshipRecord),
		ErrorCode:        www.StatusSuccess,
	}
	return &npr, nil
}

// ProcessSetProposalStatus changes the status of an existing proposal
// from unreviewed to either published or censored.
func (b *backend) ProcessSetProposalStatus(sps www.SetProposalStatus) (*www.SetProposalStatusReply, error) {
	var reply pd.SetUnvettedStatusReply
	if b.test {
		reply = pd.SetUnvettedStatusReply{
			Status: convertPropStatusFromWWW(sps.ProposalStatus),
		}
	} else {
		challenge, err := util.Random(pd.ChallengeSize)
		if err != nil {
			return nil, err
		}

		sus := pd.SetUnvettedStatus{
			Token:     sps.Token,
			Status:    convertPropStatusFromWWW(sps.ProposalStatus),
			Challenge: hex.EncodeToString(challenge),
		}

		responseBody, err := b.makeRequest(http.MethodPost, pd.SetUnvettedStatusRoute, sus)
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(responseBody, &reply)
		if err != nil {
			return nil, fmt.Errorf("Could not unmarshal SetUnvettedStatusReply: %v", err)
		}

		// Verify the challenge.
		err = util.VerifyChallenge(b.cfg.Identity, challenge, reply.Response)
		if err != nil {
			return nil, err
		}
	}

	// Update the cached proposal with the new status and return the reply.
	for k, v := range b.inventory {
		if v.CensorshipRecord.Token == sps.Token {
			s := convertPropStatusFromPD(reply.Status)
			b.inventory[k].Status = s
			spsr := www.SetProposalStatusReply{
				ProposalStatus: s,
			}
			return &spsr, nil
		}
	}

	spsr := www.SetProposalStatusReply{
		ErrorCode: www.StatusProposalNotFound,
	}
	return &spsr, nil
}

// ProcessProposalDetails tries to fetch the full details of a proposal from politeiad.
func (b *backend) ProcessProposalDetails(token string) (*www.ProposalDetailsReply, error) {
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	var cachedProposal *www.ProposalRecord
	for _, v := range b.inventory {
		if v.CensorshipRecord.Token == token {
			cachedProposal = &v
			break
		}
	}
	if cachedProposal == nil {
		pdr := www.ProposalDetailsReply{
			ErrorCode: www.StatusProposalNotFound,
		}
		return &pdr, nil
	}

	var isVettedProposal bool
	var requestObject interface{}
	if cachedProposal.Status == www.PropStatusPublic {
		isVettedProposal = true
		requestObject = pd.GetVetted{
			Token:     token,
			Challenge: hex.EncodeToString(challenge),
		}
	} else {
		isVettedProposal = false
		requestObject = pd.GetUnvetted{
			Token:     token,
			Challenge: hex.EncodeToString(challenge),
		}
	}

	var pdr www.ProposalDetailsReply
	if b.test {
		pdr = www.ProposalDetailsReply{
			ErrorCode: www.StatusSuccess,
			Proposal:  *cachedProposal,
		}
	} else {
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
		var proposal pd.ProposalRecord
		if isVettedProposal {
			var reply pd.GetVettedReply
			err = json.Unmarshal(responseBody, &reply)
			if err != nil {
				return nil, fmt.Errorf("Could not unmarshal "+
					"GetVettedReply: %v", err)
			}

			response = reply.Response
			proposal = reply.Proposal
		} else {
			var reply pd.GetUnvettedReply
			err = json.Unmarshal(responseBody, &reply)
			if err != nil {
				return nil, fmt.Errorf("Could not unmarshal "+
					"GetUnvettedReply: %v", err)
			}

			response = reply.Response
			proposal = reply.Proposal
		}

		// Verify the challenge.
		err = util.VerifyChallenge(b.cfg.Identity, challenge, response)
		if err != nil {
			return nil, err
		}

		pdr = www.ProposalDetailsReply{
			ErrorCode: www.StatusSuccess,
			Proposal:  convertPropFromPD(proposal),
		}
	}

	return &pdr, nil
}

// ProcessPolicy returns the details of Politeia's restrictions on file uploads.
func (b *backend) ProcessPolicy() *www.PolicyReply {
	return &www.PolicyReply{
		MaxImages:      www.PolicyMaxImages,
		MaxImageSize:   www.PolicyMaxImageSize,
		MaxMDs:         www.PolicyMaxMDs,
		MaxMDSize:      www.PolicyMaxMDSize,
		ValidMIMETypes: mime.ValidMimeTypes(),
		ErrorCode:      www.StatusSuccess,
	}
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
