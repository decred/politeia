package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"text/template"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/dajohi/goemail"
	v1d "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/mime"
	v1w "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/database"
	"github.com/decred/politeia/politeiawww/database/localdb"
	"github.com/decred/politeia/util"
	"github.com/kennygrant/sanitize"
)

// politeiawww backend construct
type backend struct {
	db        database.Database
	cfg       *config
	inventory []v1d.ProposalRecord

	// These properties are only used for testing.
	test                   bool
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

// emailVerificationLink emails the link with the verification token
// if the email server is set up.
func (b *backend) emailVerificationLink(email, token string) error {
	if b.cfg.SMTP == nil {
		return nil
	}

	html, err := ioutil.ReadFile("email_template.html")
	if err != nil {
		return err
	}
	tpl, err := template.New("email_template").Parse(string(html))
	if err != nil {
		return err
	}

	l, err := url.Parse(b.cfg.WebServerAddress + v1w.RouteVerifyNewUser)
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
	tpl.Execute(&buf, &tplData)

	from := "noreply@decred.org"
	subject := "Politeia Registration - Verify Your Email"
	body := string(buf.String())

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
func (b *backend) remoteInventory() (*v1d.InventoryReply, error) {
	challenge, err := util.Random(v1d.ChallengeSize)
	if err != nil {
		return nil, err
	}
	inv := v1d.Inventory{
		Challenge:     hex.EncodeToString(challenge),
		IncludeFiles:  false,
		VettedCount:   0,
		BranchesCount: 0,
	}

	responseBody, err := b.makeRequest(http.MethodPost, v1d.InventoryRoute, inv)
	if err != nil {
		return nil, err
	}

	var ir v1d.InventoryReply
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

func (b *backend) validateProposal(np v1w.NewProposal) (v1w.StatusT, error) {
	// Check for a non-empty name.
	if np.Name == "" {
		return v1w.StatusProposalMissingName, nil
	}

	// Check for at least 1 markdown file with a non-emtpy payload.
	if len(np.Files) == 0 || np.Files[0].Payload == "" {
		return v1w.StatusProposalMissingDescription, nil
	}

	// Check that the file number policy is followed.
	var numMDs, numImages uint = 0, 0
	var mdExceedsMaxSize, imageExceedsMaxSize bool = false, false
	for _, v := range np.Files {
		if strings.HasPrefix(v.MIME, "image/") {
			numImages++
			data, err := base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				return v1w.StatusInvalid, err
			}
			if len(data) > v1w.PolicyMaxImageSize {
				imageExceedsMaxSize = true
			}
		} else {
			numMDs++
			data, err := base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				return v1w.StatusInvalid, err
			}
			if len(data) > v1w.PolicyMaxMDSize {
				mdExceedsMaxSize = true
			}
		}
	}

	if numMDs > v1w.PolicyMaxMDs {
		return v1w.StatusMaxMDsExceededPolicy, nil
	}

	if numImages > v1w.PolicyMaxImages {
		return v1w.StatusMaxImagesExceededPolicy, nil
	}

	if mdExceedsMaxSize {
		return v1w.StatusMaxMDSizeExceededPolicy, nil
	}

	if imageExceedsMaxSize {
		return v1w.StatusMaxImageSizeExceededPolicy, nil
	}

	return v1w.StatusSuccess, nil
}

// LoadInventory fetches the entire inventory of proposals from politeiad
// and caches it, sorted by most recent timestamp.
func (b *backend) LoadInventory() error {
	var inv *v1d.InventoryReply
	if b.test {
		// Split the existing inventory into vetted and unvetted.
		vetted := make([]v1d.ProposalRecord, 0, 0)
		unvetted := make([]v1d.ProposalRecord, 0, 0)

		for _, v := range b.inventory {
			if v.Status == v1d.StatusPublic {
				vetted = append(vetted, v)
			} else {
				unvetted = append(unvetted, v)
			}
		}

		inv = &v1d.InventoryReply{
			Vetted:   vetted,
			Branches: unvetted,
		}
	} else {
		// Fetch remote inventory.
		var err error
		inv, err = b.remoteInventory()
		if err != nil {
			return fmt.Errorf("LoadInventory: %v", err)
		}

		log.Infof("Adding %v vetted, %v unvetted proposals to the cache", len(inv.Vetted), len(inv.Branches))
	}

	b.inventory = make([]v1d.ProposalRecord, 0, len(inv.Vetted)+len(inv.Branches))
	for _, v := range append(inv.Vetted, inv.Branches...) {
		len := len(b.inventory)
		if len == 0 {
			b.inventory = append(b.inventory, v)
		} else {
			idx := sort.Search(len, func(i int) bool {
				return v.Timestamp < b.inventory[i].Timestamp
			})

			b.inventory = append(b.inventory[:idx], append([]v1d.ProposalRecord{v}, b.inventory[idx:]...)...)
		}
	}

	return nil
}

// ProcessNewUser creates a new user in the db if it doesn't already
// exist and sets a verification token and expiry; the token must be
// verified before it expires. If the user already exists in the db
// and its token is expired, it generates a new one.
func (b *backend) ProcessNewUser(u v1w.NewUser) (*v1w.NewUserReply, string, error) {
	var token []byte
	var expiry int64

	// Check if the user already exists.
	if user, err := b.db.UserGet(u.Email); err == nil {
		// Check if the user is already verified.
		if user.VerificationToken == nil {
			reply := v1w.NewUserReply{
				ErrorCode: v1w.StatusSuccess,
			}
			return &reply, "", nil
		}

		// Check if the verification token hasn't expired yet.
		if currentTime := time.Now().Unix(); currentTime < user.VerificationExpiry {
			reply := v1w.NewUserReply{
				ErrorCode: v1w.StatusSuccess,
			}
			return &reply, "", nil
		}

		// Generate a new verification token and expiry.
		token, expiry, err = b.generateVerificationTokenAndExpiry()
		if err != nil {
			reply := v1w.NewUserReply{
				ErrorCode: v1w.StatusInvalid,
			}
			return &reply, "", err
		}

		// Add the updated user information to the db.
		user.VerificationToken = token
		user.VerificationExpiry = expiry
		err = b.db.UserUpdate(*user)
		if err != nil {
			reply := v1w.NewUserReply{
				ErrorCode: v1w.StatusInvalid,
			}
			return &reply, "", err
		}
	} else {
		// Hash the user's password.
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.Password),
			bcrypt.DefaultCost)
		if err != nil {
			reply := v1w.NewUserReply{
				ErrorCode: v1w.StatusInvalid,
			}
			return &reply, "", err
		}

		// Generate the verification token and expiry.
		token, expiry, err = b.generateVerificationTokenAndExpiry()
		if err != nil {
			reply := v1w.NewUserReply{
				ErrorCode: v1w.StatusInvalid,
			}
			return &reply, "", err
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
				reply := v1w.NewUserReply{
					ErrorCode: v1w.StatusMalformedEmail,
				}
				return &reply, "", nil
			}

			reply := v1w.NewUserReply{
				ErrorCode: v1w.StatusInvalid,
			}
			return &reply, "", err
		}
	}

	if !b.test {
		err := b.emailVerificationLink(u.Email, hex.EncodeToString(token))
		if err != nil {
			reply := v1w.NewUserReply{
				ErrorCode: v1w.StatusInvalid,
			}
			return &reply, "", err
		}
	}

	// Reply with an empty response, which indicates success.
	reply := v1w.NewUserReply{
		ErrorCode: v1w.StatusSuccess,
	}
	return &reply, hex.EncodeToString(token), nil
}

// ProcessVerifyNewUser verifies the token generated for a recently created user.
// It ensures that the token matches with the input and that the token hasn't expired.
func (b *backend) ProcessVerifyNewUser(u v1w.VerifyNewUser) (v1w.StatusT, error) {
	// Check that the user already exists.
	user, err := b.db.UserGet(u.Email)
	if err != nil {
		if err == database.ErrUserNotFound {
			return v1w.StatusVerificationTokenInvalid, nil
		}
		return v1w.StatusSuccess, err
	}

	// Decode the verification token.
	token, err := hex.DecodeString(u.VerificationToken)
	if err != nil {
		return v1w.StatusVerificationTokenInvalid, err
	}

	// Check that the verification token matches.
	if !bytes.Equal(token, user.VerificationToken) {
		return v1w.StatusVerificationTokenInvalid, nil
	}

	// Check that the token hasn't expired.
	if currentTime := time.Now().Unix(); currentTime > user.VerificationExpiry {
		return v1w.StatusVerificationTokenExpired, nil
	}

	// Clear out the verification token fields in the db.
	user.VerificationToken = nil
	user.VerificationExpiry = 0
	err = b.db.UserUpdate(*user)
	if err != nil {
		return v1w.StatusInvalid, err
	}

	return v1w.StatusSuccess, nil
}

// ProcessLogin checks that a user exists, is verified, and has
// the correct password.
func (b *backend) ProcessLogin(l v1w.Login) (*v1w.LoginReply, error) {
	// Get user from db.
	user, err := b.db.UserGet(l.Email)
	if err != nil {
		if err == database.ErrUserNotFound {
			reply := v1w.LoginReply{
				ErrorCode: v1w.StatusInvalidEmailOrPassword,
			}
			return &reply, nil
		}
		return nil, err
	}

	// Check that the user is verified.
	if user.VerificationToken != nil {
		reply := v1w.LoginReply{
			ErrorCode: v1w.StatusInvalidEmailOrPassword,
		}
		return &reply, nil
	}

	// Check the user's password.
	err = bcrypt.CompareHashAndPassword(user.HashedPassword,
		[]byte(l.Password))
	if err != nil {
		reply := v1w.LoginReply{
			ErrorCode: v1w.StatusInvalidEmailOrPassword,
		}
		return &reply, nil
	}

	reply := v1w.LoginReply{
		User: v1w.User{
			ID:    user.ID,
			Email: user.Email,
			Admin: user.Admin,
		},
		ErrorCode: v1w.StatusSuccess,
	}
	return &reply, nil
}

// ProcessAllVetted returns an array of all vetted proposals in reverse order,
// because they're sorted by oldest timestamp first.
func (b *backend) ProcessAllVetted() *v1w.GetAllVettedReply {
	proposals := make([]v1d.ProposalRecord, 0, 0)
	for i := len(b.inventory) - 1; i >= 0; i-- {
		if b.inventory[i].Status == v1d.StatusPublic {
			proposals = append(proposals, b.inventory[i])
		}
	}

	vr := v1w.GetAllVettedReply{
		Proposals: proposals,
	}
	return &vr
}

// ProcessAllUnvetted returns an array of all unvetted proposals in reverse order,
// because they're sorted by oldest timestamp first.
func (b *backend) ProcessAllUnvetted() *v1w.GetAllUnvettedReply {
	proposals := make([]v1d.ProposalRecord, 0, 0)
	for i := len(b.inventory) - 1; i >= 0; i-- {
		if b.inventory[i].Status == v1d.StatusNotReviewed {
			proposals = append(proposals, b.inventory[i])
		}
	}

	ur := v1w.GetAllUnvettedReply{
		Proposals: proposals,
	}
	return &ur
}

// ProcessNewProposal tries to submit a new proposal to politeiad.
func (b *backend) ProcessNewProposal(np v1w.NewProposal) (*v1w.NewProposalReply, error) {
	status, err := b.validateProposal(np)
	if err != nil {
		return nil, err
	}
	if status != v1w.StatusSuccess {
		reply := v1w.NewProposalReply{
			ErrorCode: status,
		}
		return &reply, nil
	}

	challenge, err := util.Random(v1d.ChallengeSize)
	if err != nil {
		return nil, err
	}

	n := v1d.New{
		Name:      sanitize.Name(np.Name),
		Challenge: hex.EncodeToString(challenge),
		Files:     np.Files,
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

	var reply v1d.NewReply
	if b.test {
		tokenBytes, err := util.Random(16)
		if err != nil {
			return nil, err
		}

		reply = v1d.NewReply{
			Timestamp: time.Now().Unix(),
			CensorshipRecord: v1d.CensorshipRecord{
				Token: hex.EncodeToString(tokenBytes),
			},
		}

		// Add the new proposal to the cache.
		b.inventory = append(b.inventory, v1d.ProposalRecord{
			Name:             np.Name,
			Status:           v1d.StatusNotReviewed,
			Timestamp:        reply.Timestamp,
			Files:            np.Files,
			CensorshipRecord: reply.CensorshipRecord,
		})
	} else {
		responseBody, err := b.makeRequest(http.MethodPost, v1d.NewRoute, n)
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
		b.inventory = append(b.inventory, v1d.ProposalRecord{
			Name:             np.Name,
			Status:           v1d.StatusNotReviewed,
			Timestamp:        reply.Timestamp,
			Files:            make([]v1d.File, 0, 0),
			CensorshipRecord: reply.CensorshipRecord,
		})
	}

	npr := v1w.NewProposalReply{
		CensorshipRecord: reply.CensorshipRecord,
		ErrorCode:        v1w.StatusSuccess,
	}
	return &npr, nil
}

// ProcessSetProposalStatus changes the status of an existing proposal
// from unreviewed to either published or censored.
func (b *backend) ProcessSetProposalStatus(sps v1w.SetProposalStatus) (*v1w.SetProposalStatusReply, error) {
	var reply v1d.SetUnvettedStatusReply
	if b.test {
		reply = v1d.SetUnvettedStatusReply{
			Status: sps.Status,
		}
	} else {
		challenge, err := util.Random(v1d.ChallengeSize)
		if err != nil {
			return nil, err
		}

		sus := v1d.SetUnvettedStatus{
			Token:     sps.Token,
			Status:    sps.Status,
			Challenge: hex.EncodeToString(challenge),
		}

		responseBody, err := b.makeRequest(http.MethodPost, v1d.SetUnvettedStatusRoute, sus)
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
			b.inventory[k].Status = reply.Status
			spsr := v1w.SetProposalStatusReply{
				Status: reply.Status,
			}
			return &spsr, nil
		}
	}

	spsr := v1w.SetProposalStatusReply{
		ErrorCode: v1w.StatusProposalNotFound,
	}
	return &spsr, nil
}

// ProcessProposalDetails tries to fetch the full details of a proposal from politeiad.
func (b *backend) ProcessProposalDetails(token string) (*v1w.ProposalDetailsReply, error) {
	challenge, err := util.Random(v1d.ChallengeSize)
	if err != nil {
		return nil, err
	}

	var cachedProposal *v1d.ProposalRecord
	for _, v := range b.inventory {
		if v.CensorshipRecord.Token == token {
			cachedProposal = &v
			break
		}
	}
	if cachedProposal == nil {
		pdr := v1w.ProposalDetailsReply{
			ErrorCode: v1w.StatusProposalNotFound,
		}
		return &pdr, nil
	}

	var isVettedProposal bool
	var requestObject interface{}
	if cachedProposal.Status == v1d.StatusPublic {
		isVettedProposal = true
		requestObject = v1d.GetVetted{
			Token:     token,
			Challenge: hex.EncodeToString(challenge),
		}
	} else {
		isVettedProposal = false
		requestObject = v1d.GetUnvetted{
			Token:     token,
			Challenge: hex.EncodeToString(challenge),
		}
	}

	var pdr v1w.ProposalDetailsReply
	if b.test {
		pdr = v1w.ProposalDetailsReply{
			Proposal: *cachedProposal,
		}
	} else {
		var route string
		if isVettedProposal {
			route = v1d.GetVettedRoute
		} else {
			route = v1d.GetUnvettedRoute
		}

		responseBody, err := b.makeRequest(http.MethodPost, route, requestObject)
		if err != nil {
			return nil, err
		}

		var response string
		var proposal v1d.ProposalRecord
		if isVettedProposal {
			var reply v1d.GetVettedReply
			err = json.Unmarshal(responseBody, &reply)
			if err != nil {
				return nil, fmt.Errorf("Could not unmarshal GetVettedReply: %v", err)
			}

			response = reply.Response
			proposal = reply.Proposal
		} else {
			var reply v1d.GetUnvettedReply
			err = json.Unmarshal(responseBody, &reply)
			if err != nil {
				return nil, fmt.Errorf("Could not unmarshal GetUnvettedReply: %v", err)
			}

			response = reply.Response
			proposal = reply.Proposal
		}

		// Verify the challenge.
		err = util.VerifyChallenge(b.cfg.Identity, challenge, response)
		if err != nil {
			return nil, err
		}

		pdr = v1w.ProposalDetailsReply{
			Proposal: proposal,
		}
	}

	return &pdr, nil
}

// ProcessPolicy returns the details of Politeia's restrictions on file uploads.
func (b *backend) ProcessPolicy() *v1w.PolicyReply {
	return &v1w.PolicyReply{
		MaxImages:      v1w.PolicyMaxImages,
		MaxImageSize:   v1w.PolicyMaxImageSize,
		MaxMDs:         v1w.PolicyMaxMDs,
		MaxMDSize:      v1w.PolicyMaxMDSize,
		ValidMIMETypes: mime.ValidMimeTypes(),
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
