package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrwallet/rpc/walletrpc"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/api/v1/mime"
	"github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/util"
	"github.com/gorilla/schema"
	"golang.org/x/net/publicsuffix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/decred/politeia/politeiawww/cmd/politeiawwwcli/config"
)

type Ctx struct {
	client *http.Client
	csrf   string

	// wallet grpc
	ctx    context.Context
	creds  credentials.TransportCredentials
	conn   *grpc.ClientConn
	wallet walletrpc.WalletServiceClient
}

type Attachment struct {
	Filename string
	Payload  []byte
}

func NewClient(skipVerify bool) (*Ctx, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: skipVerify,
	}
	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	jar, err := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})
	if err != nil {
		return nil, err
	}
	return &Ctx{
		client: &http.Client{
			Transport: tr,
			Jar:       jar,
		},
	}, nil
}

func (c *Ctx) newWalletClient() error {
	creds, err := credentials.NewClientTLSFromFile(config.WalletCert, "")
	if err != nil {
		return err
	}
	fmt.Println(config.WalletHost)
	conn, err := grpc.Dial("127.0.0.1:19111", grpc.WithTransportCredentials(creds))
	if err != nil {
		return err
	}
	wallet := walletrpc.NewWalletServiceClient(conn)

	c.ctx = context.Background()
	c.creds = creds
	c.conn = conn
	c.wallet = wallet
	return nil
}

func (c *Ctx) makeRequest(method, route string, b interface{}) ([]byte, error) {
	var requestBody []byte
	var queryParams string
	if b != nil {
		if method == http.MethodGet {
			// GET requests don't have a request body; instead we will populate
			// the query params.
			form := url.Values{}
			err := schema.NewEncoder().Encode(b, form)
			if err != nil {
				return nil, err
			}

			queryParams = "?" + form.Encode()
		} else {
			var err error
			requestBody, err = json.Marshal(b)
			if err != nil {
				return nil, err
			}
		}
	}

	fullRoute := config.Host + v1.PoliteiaWWWAPIRoute + route + queryParams

	// if --verbose flag is used, print everything and pretty print json
	// if --json flag is used, only print the raw json from req and resp bodies
	// if neither flags are used, only print request method and route
	if !config.PrintJSON {
		fmt.Printf("Request: %v %v\n", method,
			v1.PoliteiaWWWAPIRoute+route+queryParams)
	}
	if config.Verbose && method != http.MethodGet {
		prettyPrintJSON(b)
	}
	if config.PrintJSON && method != http.MethodGet {
		fmt.Printf("%v\n", string(requestBody))
	}

	req, err := http.NewRequest(method, fullRoute, bytes.NewReader(requestBody))
	if err != nil {
		return nil, err
	}
	req.Header.Add(v1.CsrfToken, c.csrf)
	r, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		r.Body.Close()
	}()

	responseBody := util.ConvertBodyToByteArray(r.Body, false)
	if r.StatusCode != http.StatusOK {
		var ue v1.UserError
		err = json.Unmarshal(responseBody, &ue)
		if err == nil {
			return nil, fmt.Errorf("%v, %v %v", r.StatusCode,
				v1.ErrorStatus[ue.ErrorCode], strings.Join(ue.ErrorContext, ", "))
		}

		return nil, fmt.Errorf("%v", r.StatusCode)
	}

	if config.Verbose {
		fmt.Printf("Response: %v\n", r.StatusCode)
	}
	if config.PrintJSON {
		fmt.Printf("%v\n", string(responseBody))
	}

	return responseBody, nil
}

func (c *Ctx) Cookies(rawurl string) ([]*http.Cookie, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}
	ck := c.client.Jar.Cookies(u)
	return ck, nil
}

func (c *Ctx) SetCookies(rawurl string, cookies []*http.Cookie) error {
	u, err := url.Parse(rawurl)
	if err != nil {
		return err
	}
	c.client.Jar.SetCookies(u, cookies)
	return nil
}

func (c *Ctx) Csrf() string {
	return c.csrf
}

func (c *Ctx) SetCsrf(csrf string) {
	c.csrf = csrf
}

func (c *Ctx) Version() (*v1.VersionReply, error) {
	requestBody, err := json.Marshal(v1.Version{})
	if err != nil {
		return nil, err
	}

	fullRoute := config.Host + v1.PoliteiaWWWAPIRoute + v1.RouteVersion

	// if --json flag is used, only print the raw json from req and resp bodies
	if !config.PrintJSON {
		fmt.Printf("Request: GET %v\n", v1.PoliteiaWWWAPIRoute+v1.RouteVersion)
	}

	// create new http request instead of using makeRequest() so that we can
	// extract the CSRF token from the header
	req, err := http.NewRequest(http.MethodGet, fullRoute,
		bytes.NewReader(requestBody))
	if err != nil {
		return nil, err
	}
	r, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		r.Body.Close()
	}()

	responseBody := util.ConvertBodyToByteArray(r.Body, false)

	if r.StatusCode != http.StatusOK {
		var ue v1.UserError
		err = json.Unmarshal(responseBody, &ue)
		if err == nil {
			return nil, fmt.Errorf("%v, %v %v", r.StatusCode,
				v1.ErrorStatus[ue.ErrorCode], strings.Join(ue.ErrorContext, ", "))
		}

		return nil, fmt.Errorf("%v", r.StatusCode)
	}

	var v v1.VersionReply
	err = json.Unmarshal(responseBody, &v)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal version: %v", err)
	}

	if config.Verbose {
		fmt.Printf("Response: %v\n", r.StatusCode)
		prettyPrintJSON(v)
	}
	if config.PrintJSON {
		fmt.Printf("%v\n", string(responseBody))
	}

	// store CSRF tokens
	c.SetCookies(config.Host, r.Cookies())
	c.csrf = r.Header.Get(v1.CsrfToken)

	return &v, nil
}

func (c *Ctx) Login(email, password string) (*v1.LoginReply, *identity.FullIdentity, error) {
	id, err := idFromString(email)
	if err != nil {
		return nil, nil, err
	}

	l := v1.Login{
		Email:    email,
		Password: digest(password),
	}

	responseBody, err := c.makeRequest("POST", v1.RouteLogin, l)
	if err != nil {
		return nil, nil, err
	}

	var lr v1.LoginReply
	err = json.Unmarshal(responseBody, &lr)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not unmarshal LoginReply: %v", err)
	}

	if config.Verbose {
		prettyPrintJSON(lr)
	}

	return &lr, id, nil
}

func (c *Ctx) Policy() (*v1.PolicyReply, error) {
	responseBody, err := c.makeRequest("GET", v1.RoutePolicy, nil)
	if err != nil {
		return nil, err
	}

	var pr v1.PolicyReply
	err = json.Unmarshal(responseBody, &pr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal PolicyReply: %v", err)
	}

	if config.Verbose {
		prettyPrintJSON(pr)
	}

	return &pr, nil
}

func (c *Ctx) NewUser(email, username, password string) (string, *identity.FullIdentity,
	string, uint64, error) {
	id, err := idFromString(email)
	if err != nil {
		return "", nil, "", 0, err
	}
	u := v1.NewUser{
		Email:     email,
		Username:  username,
		Password:  digest(password),
		PublicKey: hex.EncodeToString(id.Public.Key[:]),
	}

	responseBody, err := c.makeRequest("POST", v1.RouteNewUser, u)
	if err != nil {
		return "", nil, "", 0, err
	}

	var nur v1.NewUserReply
	err = json.Unmarshal(responseBody, &nur)
	if err != nil {
		return "", nil, "", 0, fmt.Errorf("Could not unmarshal NewUserReply: %v",
			err)
	}

	if config.Verbose {
		prettyPrintJSON(nur)
	}

	return nur.VerificationToken, id, nur.PaywallAddress, nur.PaywallAmount, nil
}

func (c *Ctx) VerifyNewUser(email, token, sig string) error {
	_, err := c.makeRequest("GET", "/user/verify", v1.VerifyNewUser{
		Email:             email,
		VerificationToken: token,
		Signature:         sig,
	})
	return err
}

func (c *Ctx) Me() (*v1.LoginReply, error) {
	l := v1.Me{}

	responseBody, err := c.makeRequest("GET", v1.RouteUserMe, l)
	if err != nil {
		return nil, err
	}

	var lr v1.LoginReply
	err = json.Unmarshal(responseBody, &lr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal LoginReply: %v", err)
	}

	if config.Verbose {
		prettyPrintJSON(lr)
	}

	return &lr, nil
}

func (c *Ctx) Secret() error {
	l := v1.Login{}
	responseBody, err := c.makeRequest("POST", v1.RouteSecret, l)

	var ue v1.UserError
	json.Unmarshal(responseBody, &ue)
	if err != nil {
		return err
	}

	if config.Verbose {
		prettyPrintJSON(ue)
	}

	return nil
}

func (c *Ctx) ChangeUsername(password, newUsername string) (
	*v1.ChangeUsernameReply, error) {
	cu := v1.ChangeUsername{
		Password:    digest(password),
		NewUsername: newUsername,
	}
	responseBody, err := c.makeRequest("POST", v1.RouteChangeUsername, cu)
	if err != nil {
		return nil, err
	}

	var cur v1.ChangeUsernameReply
	err = json.Unmarshal(responseBody, &cur)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal ChangeUsernameReply: %v",
			err)
	}

	if config.Verbose {
		prettyPrintJSON(cur)
	}

	return &cur, nil
}

func (c *Ctx) ChangePassword(currentPassword, newPassword string) (
	*v1.ChangePasswordReply, error) {
	cp := v1.ChangePassword{
		CurrentPassword: digest(currentPassword),
		NewPassword:     digest(newPassword),
	}
	responseBody, err := c.makeRequest("POST", v1.RouteChangePassword, cp)
	if err != nil {
		return nil, err
	}

	var cpr v1.ChangePasswordReply
	err = json.Unmarshal(responseBody, &cpr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal ChangePasswordReply: %v",
			err)
	}

	if config.Verbose {
		prettyPrintJSON(cpr)
	}

	return &cpr, nil
}

func (c *Ctx) ResetPassword(email, newPassword string) error {
	rp := v1.ResetPassword{
		Email: email,
	}
	responseBody, err := c.makeRequest("POST", v1.RouteResetPassword, rp)
	if err != nil {
		return err
	}

	var rpr v1.ResetPasswordReply
	err = json.Unmarshal(responseBody, &rpr)
	if err != nil {
		return fmt.Errorf("Could not unmarshal ResetPasswordReply: %v", err)
	}

	rp.NewPassword = digest(newPassword)
	rp.VerificationToken = rpr.VerificationToken

	responseBody, err = c.makeRequest("POST", v1.RouteResetPassword, rp)
	if err != nil {
		return err
	}

	err = json.Unmarshal(responseBody, &rpr)
	if err != nil {
		return fmt.Errorf("Could not unmarshal ResetPasswordReply: %v", err)
	}

	if config.Verbose {
		prettyPrintJSON(rpr)
	}

	return nil
}

func (c *Ctx) Logout() error {
	l := v1.Logout{}
	_, err := c.makeRequest("GET", v1.RouteLogout, l)
	return err
}

func (c *Ctx) ProposalPaywall() (*v1.ProposalPaywallDetailsReply, error) {
	ppd := v1.ProposalPaywallDetails{}
	responseBody, err := c.makeRequest("GET", v1.RouteProposalPaywallDetails, ppd)
	if err != nil {
		return nil, err
	}

	var ppdr v1.ProposalPaywallDetailsReply
	err = json.Unmarshal(responseBody, &ppdr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal ProposalPaywalDetailsReply: %v", err)
	}

	if config.Verbose {
		prettyPrintJSON(ppdr)
	}

	return &ppdr, nil
}

func (c *Ctx) NewProposal(id *identity.FullIdentity, mdPayload []byte, attachments []Attachment) (*v1.NewProposalReply, error) {
	np := v1.NewProposal{
		Files:     make([]v1.File, 0),
		PublicKey: hex.EncodeToString(id.Public.Key[:]),
	}

	// Process markdown file.
	mimeType := http.DetectContentType(mdPayload)
	if !mime.MimeValid(mimeType) {
		return nil, fmt.Errorf("unsupported mime type")
	}
	digest := hex.EncodeToString(util.Digest(mdPayload))
	payload := base64.StdEncoding.EncodeToString(mdPayload)

	np.Files = append(np.Files, v1.File{
		Name:    "index.md",
		MIME:    mimeType,
		Digest:  digest,
		Payload: payload,
	})

	// Process attachment files.
	for _, a := range attachments {
		mimeType := http.DetectContentType(a.Payload)
		if !mime.MimeValid(mimeType) {
			return nil, fmt.Errorf("unsupported mime type")
		}
		digest := hex.EncodeToString(util.Digest(a.Payload))
		payload := base64.StdEncoding.EncodeToString(a.Payload)

		np.Files = append(np.Files, v1.File{
			Name:    filepath.Base(a.Filename),
			MIME:    mimeType,
			Digest:  digest,
			Payload: payload,
		})
	}

	// Sign proposal merkle root.
	sig, err := proposalSignature(np.Files, id)
	if err != nil {
		return nil, fmt.Errorf("Could not sign proposal files: %v", err)
	}
	np.Signature = sig

	responseBody, err := c.makeRequest("POST", v1.RouteNewProposal, np)
	if err != nil {
		return nil, err
	}

	var npr v1.NewProposalReply
	err = json.Unmarshal(responseBody, &npr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal NewProposalReply: %v", err)
	}

	if config.Verbose {
		prettyPrintJSON(npr)
	}

	return &npr, nil
}

func (c *Ctx) EditProposal(id *identity.FullIdentity, mdPayload []byte, attachments []Attachment, token string) (*v1.EditProposalReply, error) {
	ep := v1.EditProposal{
		Files:     make([]v1.File, 0),
		PublicKey: hex.EncodeToString(id.Public.Key[:]),
	}

	// Process markdown file.
	mimeType := http.DetectContentType(mdPayload)
	if !mime.MimeValid(mimeType) {
		return nil, fmt.Errorf("unsupported mime type")
	}
	digest := hex.EncodeToString(util.Digest(mdPayload))
	payload := base64.StdEncoding.EncodeToString(mdPayload)

	ep.Files = append(ep.Files, v1.File{
		Name:    "index.md",
		MIME:    mimeType,
		Digest:  digest,
		Payload: payload,
	})

	// Process attachment files.
	for _, a := range attachments {
		mimeType := http.DetectContentType(a.Payload)
		if !mime.MimeValid(mimeType) {
			return nil, fmt.Errorf("unsupported mime type")
		}
		digest := hex.EncodeToString(util.Digest(a.Payload))
		payload := base64.StdEncoding.EncodeToString(a.Payload)

		ep.Files = append(ep.Files, v1.File{
			Name:    filepath.Base(a.Filename),
			MIME:    mimeType,
			Digest:  digest,
			Payload: payload,
		})
	}

	// Sign proposal merkle root.
	sig, err := proposalSignature(ep.Files, id)
	if err != nil {
		return nil, fmt.Errorf("Could not sign proposal files: %v", err)
	}
	ep.Signature = sig
	ep.Token = token

	responseBody, err := c.makeRequest("POST", v1.RouteEditProposal, ep)
	if err != nil {
		return nil, err
	}

	var epr v1.EditProposalReply
	err = json.Unmarshal(responseBody, &epr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal EditProposalReply: %v", err)
	}

	if config.Verbose {
		prettyPrintJSON(epr)
	}

	return &epr, nil
}

func (c *Ctx) GetProp(token, serverPubKey string) (*v1.ProposalDetailsReply, error) {
	responseBody, err := c.makeRequest("GET", "/proposals/"+token, nil)
	if err != nil {
		return nil, err
	}

	var pr v1.ProposalDetailsReply
	err = json.Unmarshal(responseBody, &pr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal GetProposalReply: %v", err)
	}

	if err = verifyProposal(pr.Proposal, serverPubKey); err != nil {
		return nil, fmt.Errorf("verifyProposal: %v", err)
	}

	if config.Verbose {
		prettyPrintJSON(pr)
	}

	return &pr, nil
}

func (c *Ctx) ProposalsForUser(userId, serverPubKey string) (*v1.UserProposalsReply, error) {
	up := v1.UserProposals{
		UserId: userId,
	}
	responseBody, err := c.makeRequest("GET", v1.RouteUserProposals, up)
	if err != nil {
		return nil, err
	}

	var upr v1.UserProposalsReply
	err = json.Unmarshal(responseBody, &upr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal UserProposalsReply: %v", err)
	}

	for _, p := range upr.Proposals {
		if err = verifyProposal(p, serverPubKey); err != nil {
			return nil, fmt.Errorf("verifyProposal: %v", err)
		}
	}

	if config.Verbose {
		prettyPrintJSON(upr)
	}

	return &upr, nil
}

func (c *Ctx) SetPropStatus(id *identity.FullIdentity, token string,
	status v1.PropStatusT, message string) (*v1.SetProposalStatusReply, error) {
	ps := v1.SetProposalStatus{
		Token:               token,
		ProposalStatus:      status,
		StatusChangeMessage: message,
	}
	// Sign token+string(status)+statuschangemessage
	msg := []byte(ps.Token + strconv.FormatUint(uint64(ps.ProposalStatus), 10) + message)
	var err error
	sig := id.SignMessage(msg)
	ps.Signature = hex.EncodeToString(sig[:])

	ps.PublicKey = hex.EncodeToString(id.Public.Key[:])

	responseBody, err := c.makeRequest("POST", "/proposals/"+token+"/status", ps)
	if err != nil {
		return nil, err
	}

	var psr v1.SetProposalStatusReply
	err = json.Unmarshal(responseBody, &psr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal "+
			"SetProposalStatusReply: %v", err)
	}

	if config.Verbose {
		prettyPrintJSON(psr)
	}

	return &psr, nil
}

func (c *Ctx) GetVetted(v v1.GetAllVetted, serverPubKey string) (*v1.GetAllVettedReply, error) {
	responseBody, err := c.makeRequest("GET", v1.RouteAllVetted, v)
	if err != nil {
		return nil, err
	}

	var vr v1.GetAllVettedReply
	err = json.Unmarshal(responseBody, &vr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal GetAllVettedReply: %v", err)
	}

	for _, p := range vr.Proposals {
		if err = verifyProposal(p, serverPubKey); err != nil {
			return nil, fmt.Errorf("verifyProposal: %v", err)
		}
	}

	if config.Verbose {
		prettyPrintJSON(vr)
	}

	return &vr, nil
}

func (c *Ctx) GetUnvetted(u v1.GetAllUnvetted, serverPubKey string) (*v1.GetAllUnvettedReply, error) {
	responseBody, err := c.makeRequest("GET", v1.RouteAllUnvetted, u)
	if err != nil {
		return nil, err
	}

	var ur v1.GetAllUnvettedReply
	err = json.Unmarshal(responseBody, &ur)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal GetAllUnvettedReply: %v", err)
	}

	if config.Verbose {
		prettyPrintJSON(ur)
	}

	for _, p := range ur.Proposals {
		if err = verifyProposal(p, serverPubKey); err != nil {
			return nil, fmt.Errorf("verifyProposal: %v", err)
		}
	}

	return &ur, nil
}

func (c *Ctx) Comment(id *identity.FullIdentity, token, comment,
	parentID string) (*v1.NewCommentReply, error) {
	cm := v1.NewComment{
		Token:    token,
		ParentID: parentID,
		Comment:  comment,
	}
	// Sign token+parentid+comment
	msg := []byte(cm.Token + cm.ParentID + cm.Comment)
	sig := id.SignMessage(msg)
	cm.Signature = hex.EncodeToString(sig[:])

	cm.PublicKey = hex.EncodeToString(id.Public.Key[:])

	responseBody, err := c.makeRequest("POST", v1.RouteNewComment, cm)
	if err != nil {
		return nil, err
	}

	var cr v1.NewCommentReply
	err = json.Unmarshal(responseBody, &cr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal CommentReply: %v", err)
	}

	if config.Verbose {
		prettyPrintJSON(cr)
	}

	return &cr, nil
}

func (c *Ctx) CommentGet(token string) (*v1.GetCommentsReply, error) {
	responseBody, err := c.makeRequest("GET", "/proposals/"+token+"/comments",
		nil)
	if err != nil {
		return nil, err
	}

	var gcr v1.GetCommentsReply
	err = json.Unmarshal(responseBody, &gcr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal GetCommentReply: %v", err)
	}

	if config.Verbose {
		prettyPrintJSON(gcr)
	}

	return &gcr, nil
}

func (c *Ctx) CommentsVotesGet(token string) (*v1.UserCommentsVotesReply, error) {
	responseBody, err := c.makeRequest("GET", "/user/proposals/"+token+"/commentsvotes",
		nil)
	if err != nil {
		return nil, err
	}

	var cvg v1.UserCommentsVotesReply
	err = json.Unmarshal(responseBody, &cvg)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal GetCommentReply: %v", err)
	}

	if config.Verbose {
		prettyPrintJSON(cvg)
	}

	return &cvg, nil
}

func (c *Ctx) CommentVote(id *identity.FullIdentity, token, commentID,
	action string) (*v1.LikeCommentReply, error) {
	lcm := v1.LikeComment{
		Token:     token,
		CommentID: commentID,
	}

	switch action {
	case "upvote":
		lcm.Action = "1"
	case "downvote":
		lcm.Action = "-1"
	}

	// Sign token+commentid+action
	act := []byte(lcm.Token + lcm.CommentID + lcm.Action)
	sig := id.SignMessage(act)

	lcm.Signature = hex.EncodeToString(sig[:])
	lcm.PublicKey = hex.EncodeToString(id.Public.Key[:])

	responseBody, err := c.makeRequest("POST", v1.RouteLikeComment, lcm)
	if err != nil {
		return nil, err
	}

	var lcr v1.LikeCommentReply
	err = json.Unmarshal(responseBody, &lcr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal VoteComment: %v", err)
	}

	if config.Verbose {
		prettyPrintJSON(lcr)
	}

	return &lcr, nil
}

func (c *Ctx) CensorComment(token, commentID, reason, signature, publicKey string) (*v1.CensorCommentReply, error) {
	cc := v1.CensorComment{
		Token:     token,
		CommentID: commentID,
		Reason:    reason,
		Signature: signature,
		PublicKey: publicKey,
	}

	responseBody, err := c.makeRequest("POST", v1.RouteCensorComment, cc)
	if err != nil {
		return nil, err
	}

	var ccr v1.CensorCommentReply
	err = json.Unmarshal(responseBody, &ccr)
	if err != nil {
		return nil, err
	}

	if config.Verbose {
		prettyPrintJSON(ccr)
	}

	return &ccr, nil
}

func (c *Ctx) StartVote(id *identity.FullIdentity, token string) (
	*v1.StartVoteReply, error) {
	sv := v1.StartVote{
		PublicKey: hex.EncodeToString(id.Public.Key[:]),
		Vote: v1.Vote{
			Token:    token,
			Mask:     0x03, // bit 0 no, bit 1 yes
			Duration: 2016,
			Options: []v1.VoteOption{
				{
					Id:          "no",
					Description: "Don't approve proposal",
					Bits:        0x01,
				},
				{
					Id:          "yes",
					Description: "Approve proposal",
					Bits:        0x02,
				},
			},
		},
	}
	sig := id.SignMessage([]byte(token))
	sv.Signature = hex.EncodeToString(sig[:])

	responseBody, err := c.makeRequest("POST", v1.RouteStartVote, sv)
	if err != nil {
		return nil, err
	}

	var svr v1.StartVoteReply
	err = json.Unmarshal(responseBody, &svr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal StartVoteReply: %v", err)
	}

	if config.Verbose {
		prettyPrintJSON(svr)
	}

	return &svr, nil
}

func (c *Ctx) CreateNewKey(email string) (*identity.FullIdentity, error) {
	id, err := idFromString(email)
	if err != nil {
		return nil, err
	}
	uuk := v1.UpdateUserKey{
		PublicKey: hex.EncodeToString(id.Public.Key[:]),
	}
	responseBody, err := c.makeRequest("POST", v1.RouteUpdateUserKey, uuk)
	if err != nil {
		return nil, err
	}

	var uukr v1.UpdateUserKeyReply
	err = json.Unmarshal(responseBody, &uukr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal UpdateUserKeyReply: %v", err)
	}

	if config.Verbose {
		prettyPrintJSON(uukr)
	}

	sig := id.SignMessage([]byte(uukr.VerificationToken))
	vuuk := v1.VerifyUpdateUserKey{
		VerificationToken: uukr.VerificationToken,
		Signature:         hex.EncodeToString(sig[:]),
	}

	responseBody, err = c.makeRequest("POST", v1.RouteVerifyUpdateUserKey, vuuk)
	if err != nil {
		return nil, err
	}

	var vuukr v1.VerifyUpdateUserKeyReply
	err = json.Unmarshal(responseBody, &vuukr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal VerifyUpdateUserKeyReply: %v",
			err)
	}

	if config.Verbose {
		prettyPrintJSON(vuukr)
	}

	return id, nil
}

func (c *Ctx) VerifyUserPayment() (*v1.VerifyUserPaymentReply,
	error) {
	v := v1.VerifyUserPayment{}
	responseBody, err := c.makeRequest("GET", v1.RouteVerifyUserPayment, v)
	if err != nil {
		return nil, err
	}

	var vr v1.VerifyUserPaymentReply
	err = json.Unmarshal(responseBody, &vr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal VerifyUserPaymentReply: %v",
			err)
	}

	if config.Verbose {
		prettyPrintJSON(vr)
	}

	return &vr, nil
}

func (c *Ctx) UsernamesById(userIds []string) (*v1.UsernamesByIdReply, error) {
	ubi := v1.UsernamesById{
		UserIds: userIds,
	}
	responseBody, err := c.makeRequest("POST", v1.RouteUsernamesById, ubi)
	if err != nil {
		return nil, err
	}

	var ubir v1.UsernamesByIdReply
	err = json.Unmarshal(responseBody, &ubir)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal UsernamesByIdReply: %v",
			err)
	}

	if config.Verbose {
		prettyPrintJSON(ubir)
	}

	return &ubir, nil
}

func (c *Ctx) ActiveVotes() (*v1.ActiveVoteReply, error) {
	av := v1.ActiveVote{}
	responseBody, err := c.makeRequest("GET", v1.RouteActiveVote, av)
	if err != nil {
		return nil, err
	}

	var avr v1.ActiveVoteReply
	err = json.Unmarshal(responseBody, &avr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal ActiveVoteReply: %v",
			err)
	}

	if config.Verbose {
		// don't print StartVoteReply. It makes the output illegible.
		for _, v := range avr.Votes {
			prettyPrintJSON(v.StartVote)
		}
	}

	return &avr, nil
}

func (c *Ctx) CastVotes(propToken, voteId string) (*v1.BallotReply, error) {
	// fetch proposals that are being voted on
	avr, err := c.ActiveVotes()
	if err != nil {
		return nil, err
	}

	// find proposal the user wants to vote on and validate the voteId
	var (
		pvt     *v1.ProposalVoteTuple
		voteBit string
	)
	for _, v := range avr.Votes {
		if v.Proposal.CensorshipRecord.Token != propToken {
			continue
		}

		// validate voteId
		found := false
		for _, options := range v.StartVote.Vote.Options {
			if options.Id == voteId {
				found = true
				voteBit = strconv.FormatUint(options.Bits, 16)
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("Vote id not found: %v", voteId)
		}

		// the correct proposal was found and the voteId was validated
		pvt = &v
		break
	}
	if pvt == nil {
		return nil, fmt.Errorf("Proposal not found: %v", propToken)
	}

	// connect go wallet
	err = c.newWalletClient()
	if err != nil {
		return nil, err
	}

	// find eligble tickets
	tix, err := convertTicketHashes(pvt.StartVoteReply.EligibleTickets)
	if err != nil {
		return nil, fmt.Errorf("Ticket pool corrupt: %v %v", propToken, err)
	}
	ctres, err := c.wallet.CommittedTickets(c.ctx,
		&walletrpc.CommittedTicketsRequest{
			Tickets: tix,
		})
	if err != nil {
		return nil, fmt.Errorf("Ticket pool verification: %v %v", propToken, err)
	}
	if len(ctres.TicketAddresses) == 0 {
		return nil, fmt.Errorf("No eligible tickets found")
	}

	// prompt user for wallet password
	passphrase, err := providePrivPassphrase()
	if err != nil {
		return nil, err
	}

	// sign tickets
	sm := &walletrpc.SignMessagesRequest{
		Passphrase: passphrase,
		Messages: make([]*walletrpc.SignMessagesRequest_Message, 0,
			len(ctres.TicketAddresses)),
	}
	for _, v := range ctres.TicketAddresses {
		h, err := chainhash.NewHash(v.Ticket)
		if err != nil {
			return nil, err
		}
		msg := propToken + h.String() + voteBit
		sm.Messages = append(sm.Messages, &walletrpc.SignMessagesRequest_Message{
			Address: v.Address,
			Message: msg,
		})
	}
	smr, err := c.wallet.SignMessages(c.ctx, sm)
	if err != nil {
		return nil, err
	}

	// validate signatures
	for k, v := range smr.Replies {
		if v.Error == "" {
			continue
		}
		return nil, fmt.Errorf("Signature failed index %v: %v", k, v.Error)
	}

	// compile votes. Note that ctres, sm and smr use the same index.
	cv := v1.Ballot{
		Votes: make([]v1.CastVote, 0, len(ctres.TicketAddresses)),
	}
	for k, v := range ctres.TicketAddresses {
		h, err := chainhash.NewHash(v.Ticket)
		if err != nil {
			return nil, err
		}
		signature := hex.EncodeToString(smr.Replies[k].Signature)
		cv.Votes = append(cv.Votes, v1.CastVote{
			Token:     propToken,
			Ticket:    h.String(),
			VoteBit:   voteBit,
			Signature: signature,
		})
	}

	// cast votes on supplied proposal
	responseBody, err := c.makeRequest("POST", v1.RouteCastVotes, &cv)
	if err != nil {
		return nil, err
	}

	var br v1.BallotReply
	err = json.Unmarshal(responseBody, &br)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal BallotReply: %v", err)
	}

	if config.Verbose {
		prettyPrintJSON(br)
	}

	return &br, nil
}

func (c *Ctx) ProposalVotes(propToken string) (*v1.VoteResultsReply, error) {

	responseBody, err := c.makeRequest("GET", "/proposals/"+propToken+"/votes", nil)
	if err != nil {
		return nil, err
	}

	var vrr v1.VoteResultsReply
	err = json.Unmarshal(responseBody, &vrr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal ProposalVotesReply: %v", err)
	}

	if config.Verbose {
		prettyPrintJSON(vrr.StartVote)
	}

	return &vrr, nil
}

func (c *Ctx) GetUserDetails(userId string) (*v1.UserDetailsReply, error) {
	responseBody, err := c.makeRequest("GET", "/user/"+userId, nil)
	if err != nil {
		return nil, err
	}

	var pr v1.UserDetailsReply
	err = json.Unmarshal(responseBody, &pr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal UserDetailsReply: %v", err)
	}

	if config.Verbose {
		prettyPrintJSON(pr)
	}

	return &pr, nil
}

func (c *Ctx) EditUser(userID string, action int64, reason string) (*v1.EditUserReply, error) {
	eu := v1.EditUser{
		UserID: userID,
		Action: v1.UserEditActionT(action),
		Reason: reason,
	}

	responseBody, err := c.makeRequest("POST", v1.RouteEditUser, eu)
	if err != nil {
		return nil, err
	}

	var eur v1.EditUserReply
	err = json.Unmarshal(responseBody, &eur)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal EditUserReply: %v", err)
	}

	if config.Verbose {
		prettyPrintJSON(eur)
	}

	return &eur, nil
}

func (c *Ctx) AuthorizeVote(token, publicKey, signature string) (*v1.AuthorizeVoteReply, error) {
	av := v1.AuthorizeVote{
		Token:     token,
		PublicKey: publicKey,
		Signature: signature,
	}
	responseBody, err := c.makeRequest("POST", "/proposals/authorizevote", av)
	if err != nil {
		return nil, err
	}

	var avr v1.AuthorizeVoteReply
	err = json.Unmarshal(responseBody, &avr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal AuthorizeVoteReply: %v", err)
	}

	if config.Verbose {
		prettyPrintJSON(avr)
	}

	return &avr, nil
}

func (c *Ctx) VoteStatus(token string) (*v1.VoteStatusReply, error) {
	route := "/proposals/" + token + "/votestatus"
	responseBody, err := c.makeRequest("GET", route, v1.VoteStatus{})
	if err != nil {
		return nil, err
	}

	var vsr v1.VoteStatusReply
	err = json.Unmarshal(responseBody, &vsr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal VoteStatusReply: %v", err)
	}

	if config.Verbose {
		prettyPrintJSON(vsr)
	}

	return &vsr, nil
}
