package client

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"

	"github.com/agl/ed25519"
	"github.com/decred/politeia/decredplugin"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/util"
	"github.com/gorilla/schema"
	"golang.org/x/net/publicsuffix"

	"github.com/decred/politeia/politeiawww/cmd/politeiawwwcli/config"
)

type Ctx struct {
	client *http.Client
	csrf   string
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
		}}, nil
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
	fmt.Printf("Request: %v %v\n", method,
		v1.PoliteiaWWWAPIRoute+route+queryParams)

	if config.PrintJson {
		fmt.Println("  " + string(requestBody))
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

	if config.PrintJson {
		fmt.Printf("Response: %v %v\n\n", r.StatusCode, string(responseBody))
	}
	if r.StatusCode != http.StatusOK {
		var ue v1.UserError
		err = json.Unmarshal(responseBody, &ue)
		if err == nil {
			return nil, fmt.Errorf("%v, %v %v", r.StatusCode,
				v1.ErrorStatus[ue.ErrorCode], strings.Join(ue.ErrorContext, ", "))
		}

		return nil, fmt.Errorf("%v", r.StatusCode)
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

func (c *Ctx) Login(email, password string) (*v1.LoginReply, error) {
	l := v1.Login{
		Email:    email,
		Password: password,
	}

	responseBody, err := c.makeRequest("POST", v1.RouteLogin, l)
	if err != nil {
		return nil, err
	}

	var lr v1.LoginReply
	err = json.Unmarshal(responseBody, &lr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal LoginReply: %v", err)
	}

	return &lr, nil
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

	return &pr, nil
}

func idFromString(s string) (*identity.FullIdentity, error) {
	// super hack alert, we are going to use the email address as the
	// privkey.  We do this in order to sign things as an admin later.
	buf := [32]byte{}
	copy(buf[:], []byte(s))
	r := bytes.NewReader(buf[:])
	pub, priv, err := ed25519.GenerateKey(r)
	if err != nil {
		return nil, err
	}
	id := &identity.FullIdentity{}
	copy(id.Public.Key[:], pub[:])
	copy(id.PrivateKey[:], priv[:])
	return id, nil
}

func (c *Ctx) NewUser(email, password string) (string, *identity.FullIdentity,
	string, uint64, error) {
	id, err := idFromString(email)
	if err != nil {
		return "", nil, "", 0, err
	}
	u := v1.NewUser{
		Email:     email,
		Password:  password,
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

	return nur.VerificationToken, id, nur.PaywallAddress, nur.PaywallAmount, nil
}

func checkNotLoggedInErr(response []byte) error {
	var ue v1.UserError
	err := json.Unmarshal(response, &ue)
	if ue.ErrorCode == v1.ErrorStatusNotLoggedIn {
		return fmt.Errorf("User not logged in: %v",
			v1.ErrorStatusNotLoggedIn)
	}
	if err != nil {
		return err
	}
	return nil
}

func (c *Ctx) VerifyNewUser(email, token, sig string) error {
	_, err := c.makeRequest("GET", "/user/verify/?email="+email+
		"&verificationtoken="+token+"&signature="+sig, nil)
	return err
}

func (c *Ctx) Me() (*v1.LoginReply, error) {
	l := v1.Me{}

	responseBody, err := c.makeRequest("GET", v1.RouteUserMe, l)
	if err != nil {
		return nil, err
	}
	err = checkNotLoggedInErr(responseBody)
	if err != nil {
		return nil, err
	}

	var lr v1.LoginReply
	err = json.Unmarshal(responseBody, &lr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal LoginReply: %v", err)
	}

	return &lr, nil
}

func (c *Ctx) Secret() error {
	l := v1.Login{}
	responseBody, err := c.makeRequest("POST", v1.RouteSecret, l)
	var ue v1.UserError
	json.Unmarshal(responseBody, &ue)
	if ue.ErrorCode == v1.ErrorStatusNotLoggedIn {
		return fmt.Errorf("User not logged in: %v", v1.ErrorStatusNotLoggedIn)
	}
	if err != nil {
		return err
	}
	return nil
}

func (c *Ctx) ChangePassword(currentPassword, newPassword string) (
	*v1.ChangePasswordReply, error) {
	cp := v1.ChangePassword{
		CurrentPassword: currentPassword,
		NewPassword:     newPassword,
	}
	responseBody, err := c.makeRequest("POST", v1.RouteChangePassword, cp)
	if err != nil {
		return nil, err
	}

	var cpr v1.ChangePasswordReply
	err = json.Unmarshal(responseBody, &cpr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal "+"ChangePasswordReply: %v",
			err)
	}

	return &cpr, nil
}

func (c *Ctx) ResetPassword(email, password, newPassword string) error {
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

	rp.NewPassword = newPassword
	rp.VerificationToken = rpr.VerificationToken

	responseBody, err = c.makeRequest("POST", v1.RouteResetPassword, rp)
	if err != nil {
		return err
	}

	err = json.Unmarshal(responseBody, &rpr)
	if err != nil {
		return fmt.Errorf("Could not unmarshal ResetPasswordReply: %v", err)
	}

	return nil
}

func (c *Ctx) Logout() error {
	l := v1.Logout{}
	_, err := c.makeRequest("GET", v1.RouteLogout, l)
	return err
}

func (c *Ctx) NewProposal(id *identity.FullIdentity) (*v1.NewProposalReply, error) {
	payload := []byte("This is a description")
	h := sha256.New()
	h.Write(payload)

	sig := id.SignMessage([]byte(hex.EncodeToString(h.Sum(nil))))
	np := v1.NewProposal{
		Files: make([]v1.File, 0),
		// We can get away with just signing the digest because there
		// is only one file.
		PublicKey: hex.EncodeToString(id.Public.Key[:]),
		Signature: hex.EncodeToString(sig[:]),
	}

	np.Files = append(np.Files, v1.File{
		Name:    "index.md",
		MIME:    "text/plain; charset=utf-8",
		Digest:  hex.EncodeToString(h.Sum(nil)),
		Payload: base64.StdEncoding.EncodeToString(payload),
	})

	responseBody, err := c.makeRequest("POST", v1.RouteNewProposal, np)
	if err != nil {
		return nil, err
	}

	err = checkNotLoggedInErr(responseBody)
	if err != nil {
		return nil, err
	}

	var vr v1.NewProposalReply
	err = json.Unmarshal(responseBody, &vr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal NewProposalReply: %v", err)
	}

	return &vr, nil
}

func (c *Ctx) GetProp(token string) (*v1.ProposalDetailsReply, error) {
	responseBody, err := c.makeRequest("GET", "/proposals/"+token, nil)
	if err != nil {
		return nil, err
	}

	var pr v1.ProposalDetailsReply
	err = json.Unmarshal(responseBody, &pr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal GetProposalReply: %v", err)
	}

	return &pr, nil
}

func (c *Ctx) ProposalsForUser(userId string) (*v1.UserProposalsReply, error) {
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

	return &upr, nil
}

func (c *Ctx) SetPropStatus(id *identity.FullIdentity, token string,
	status v1.PropStatusT) (*v1.SetProposalStatusReply, error) {
	ps := v1.SetProposalStatus{
		Token:          token,
		ProposalStatus: status,
	}
	// Sign token+string(status)
	msg := []byte(ps.Token + strconv.FormatUint(uint64(ps.ProposalStatus), 10))
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

	return &psr, nil
}

func (c *Ctx) GetVetted(v v1.GetAllVetted) (*v1.GetAllVettedReply, error) {
	responseBody, err := c.makeRequest("GET", v1.RouteAllVetted, v)
	if err != nil {
		return nil, err
	}

	var vr v1.GetAllVettedReply
	err = json.Unmarshal(responseBody, &vr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal GetAllVettedReply: %v", err)
	}

	return &vr, nil
}

func (c *Ctx) GetUnvetted(u v1.GetAllUnvetted) (*v1.GetAllUnvettedReply,
	error) {
	responseBody, err := c.makeRequest("GET", v1.RouteAllUnvetted, u)
	if err != nil {
		return nil, err
	}

	var ur v1.GetAllUnvettedReply
	err = json.Unmarshal(responseBody, &ur)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal GetAllUnvettedReply: %v", err)
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

	return &gcr, nil
}

func (c *Ctx) StartVote(id *identity.FullIdentity, token string) (
	*v1.StartVoteReply, error) {
	sv := v1.StartVote{
		PublicKey: hex.EncodeToString(id.Public.Key[:]),
		Vote: decredplugin.Vote{
			Token:    token,
			Mask:     0x03, // bit 0 no, bit 1 yes
			Duration: 2016,
			Options: []decredplugin.VoteOption{
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

	return id, nil
}

func (c *Ctx) VerifyUserPayment(txid string) (*v1.VerifyUserPaymentTxReply,
	error) {
	v := v1.VerifyUserPaymentTx{
		TxId: txid,
	}
	responseBody, err := c.makeRequest("GET", v1.RouteVerifyUserPaymentTx, v)
	if err != nil {
		return nil, err
	}

	var vr v1.VerifyUserPaymentTxReply
	err = json.Unmarshal(responseBody, &vr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal VerifyUserPaymentTxReply: %v",
			err)
	}

	return &vr, nil
}
