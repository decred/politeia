package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/gorilla/schema"

	"golang.org/x/net/publicsuffix"

	"github.com/agl/ed25519"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/util"
)

type ctx struct {
	client *http.Client
	csrf   string
}

func newClient(skipVerify bool) (*ctx, error) {
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
	return &ctx{
		client: &http.Client{
			Transport: tr,
			Jar:       jar,
		}}, nil
}

func (c *ctx) makeRequest(method string, route string, b interface{}) ([]byte, error) {
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

	fullRoute := *host + v1.PoliteiaWWWAPIRoute + route + queryParams
	fmt.Printf("Request: %v %v\n", method, v1.PoliteiaWWWAPIRoute+route+queryParams)

	if *printJson {
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
	if *printJson {
		fmt.Printf("Response: %v %v\n\n", r.StatusCode, string(responseBody))
	}
	if r.StatusCode != http.StatusOK {
		var ue v1.UserError
		err = json.Unmarshal(responseBody, &ue)
		if err == nil {
			return nil, fmt.Errorf("%v, %v %v", r.StatusCode,
				v1.ErrorStatus[ue.ErrorCode],
				strings.Join(ue.ErrorContext, ", "))
		}

		return nil, fmt.Errorf("%v", r.StatusCode)
	}

	return responseBody, nil
}

func (c *ctx) getCSRF() (*v1.VersionReply, error) {
	requestBody, err := json.Marshal(v1.Version{})
	if err != nil {
		return nil, err
	}

	fmt.Printf("Request: GET /\n")

	if *printJson {
		fmt.Println("  " + string(requestBody))
	}

	req, err := http.NewRequest(http.MethodGet, *host, bytes.NewReader(requestBody))
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
	if *printJson {
		fmt.Println("Response: " + string(responseBody) + "\n")
	}
	if r.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%v", r.StatusCode)
	}

	var v v1.VersionReply
	err = json.Unmarshal(responseBody, &v)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal version: %v", err)
	}

	c.csrf = r.Header.Get(v1.CsrfToken)

	return &v, nil
}

func (c *ctx) policy() (*v1.PolicyReply, error) {
	responseBody, err := c.makeRequest("GET", v1.RoutePolicy, nil)
	if err != nil {
		return nil, err
	}

	var pr v1.PolicyReply
	err = json.Unmarshal(responseBody, &pr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal PolicyReply: %v",
			err)
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

func (c *ctx) newUser(email string, password string) (string, *identity.FullIdentity, string, uint64, error) {
	id, err := idFromString(email)
	if err != nil {
		return "", nil, "", 0, err
	}
	u := v1.NewUser{
		Email:     email,
		Password:  password,
		Username:  password,
		PublicKey: hex.EncodeToString(id.Public.Key[:]),
	}

	responseBody, err := c.makeRequest("POST", v1.RouteNewUser, u)
	if err != nil {
		return "", nil, "", 0, err
	}

	var nur v1.NewUserReply
	err = json.Unmarshal(responseBody, &nur)
	if err != nil {
		return "", nil, "", 0,
			fmt.Errorf("Could not unmarshal NewUserReply: %v", err)
	}

	//fmt.Printf("Verification Token: %v\n", nur.VerificationToken)
	return nur.VerificationToken, id, nur.PaywallAddress, nur.PaywallAmount, nil
}

func (c *ctx) verifyNewUser(email, token, sig string) error {
	_, err := c.makeRequest("GET", "/user/verify/?email="+email+
		"&verificationtoken="+token+"&signature="+sig, nil)
	return err
}

func (c *ctx) getUserCommentsVotes(token string) (*v1.UserCommentsVotesReply, error) {
	responseBody, err := c.makeRequest("GET", "/user/proposals/"+token+"/commentsvotes", nil)
	if err != nil {
		return nil, err
	}

	var ucvr v1.UserCommentsVotesReply
	err = json.Unmarshal(responseBody, &ucvr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal UserCommentsVotesReply: %v",
			err)
	}

	return &ucvr, nil
}

func (c *ctx) verifyUserPayment(id *identity.FullIdentity, token string) (*v1.VerifyUserPaymentReply, error) {
	vup := v1.VerifyUserPayment{}
	responseBody, err := c.makeRequest("GET", v1.RouteVerifyUserPayment, vup)
	if err != nil {
		return nil, err
	}

	var vupr v1.VerifyUserPaymentReply
	err = json.Unmarshal(responseBody, &vupr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal verifyUserPaidReply: %v",
			err)
	}

	return &vupr, nil
}

func (c *ctx) login(email, password string) (*v1.LoginReply, error) {
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
		return nil, fmt.Errorf("Could not unmarshal LoginReply: %v",
			err)
	}

	return &lr, nil
}

func (c *ctx) secret() error {
	l := v1.Login{}
	responseBody, err := c.makeRequest("POST", v1.RouteSecret, l)
	var ue v1.UserError
	json.Unmarshal(responseBody, &ue)
	if ue.ErrorCode == v1.ErrorStatusNotLoggedIn {
		return fmt.Errorf("User not logged in: %v",
			v1.ErrorStatusNotLoggedIn)
	}
	if err != nil {
		return err
	}
	return nil
}

func (c *ctx) like(id *identity.FullIdentity, token, commentID, action string) (*v1.LikeCommentReply, error) {
	lc := v1.LikeComment{
		Token:     token,
		CommentID: commentID,
		Action:    action,
	}
	// Sign token+commentid+action
	msg := []byte(lc.Token + lc.CommentID + lc.Action)
	sig := id.SignMessage(msg)
	lc.Signature = hex.EncodeToString(sig[:])
	lc.PublicKey = hex.EncodeToString(id.Public.Key[:])

	responseBody, err := c.makeRequest("POST", v1.RouteLikeComment, lc)
	if err != nil {
		return nil, err
	}

	var lcr v1.LikeCommentReply
	err = json.Unmarshal(responseBody, &lcr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal LikeCommentReply: %v",
			err)
	}

	return &lcr, nil
}

func (c *ctx) comment(id *identity.FullIdentity, token, comment, parentID string) (*v1.NewCommentReply, error) {
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
		return nil, fmt.Errorf("Could not unmarshal CommentReply: %v",
			err)
	}

	return &cr, nil
}

func (c *ctx) commentGet(token string) (*v1.GetCommentsReply, error) {
	responseBody, err := c.makeRequest("GET", "/proposals/"+token+
		"/comments", nil)
	if err != nil {
		return nil, err
	}

	var gcr v1.GetCommentsReply
	err = json.Unmarshal(responseBody, &gcr)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal GetCommentReply: %v",
			err)
	}

	return &gcr, nil
}

func (c *ctx) startVote(id *identity.FullIdentity, token string) (*v1.StartVoteReply, error) {
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
		return nil, fmt.Errorf("Could not unmarshal StartVoteReply: %v",
			err)
	}

	return &svr, nil
}

func (c *ctx) me() (*v1.LoginReply, error) {
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
		return nil, fmt.Errorf("Could not unmarshal LoginReply: %v",
			err)
	}

	return &lr, nil
}

func (c *ctx) newProposal(id *identity.FullIdentity) (*v1.NewProposalReply, error) {
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
		return nil,
			fmt.Errorf("Could not unmarshal NewProposalReply: %v",
				err)
	}

	return &vr, nil
}

func (c *ctx) allVetted() error {
	responseBody, err := c.makeRequest("GET", v1.RouteAllVetted,
		v1.GetAllVetted{})
	if err != nil {
		return err
	}

	var vr v1.GetAllVettedReply
	err = json.Unmarshal(responseBody, &vr)
	if err != nil {
		return fmt.Errorf("Could not unmarshal GetAllVettedReply: %v",
			err)
	}

	return nil
}

func (c *ctx) allUnvetted(after string) (*v1.GetAllUnvettedReply, error) {
	u := v1.GetAllUnvetted{
		After: after,
	}
	responseBody, err := c.makeRequest("GET", v1.RouteAllUnvetted, u)
	if err != nil {
		return nil, err
	}

	var ur v1.GetAllUnvettedReply
	err = json.Unmarshal(responseBody, &ur)
	if err != nil {
		return nil,
			fmt.Errorf("Could not unmarshal GetAllUnvettedReply: %v",
				err)
	}

	return &ur, nil
}

func (c *ctx) proposalsForUser(userId string) (*v1.UserProposalsReply, error) {
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
		return nil,
			fmt.Errorf("Could not unmarshal UserProposalsReply: %v",
				err)
	}

	return &upr, nil
}

func (c *ctx) getProp(token string) (*v1.ProposalDetailsReply, error) {
	responseBody, err := c.makeRequest("GET", "/proposals/"+token, nil)
	if err != nil {
		return nil, err
	}

	var pr v1.ProposalDetailsReply
	err = json.Unmarshal(responseBody, &pr)
	if err != nil {
		return nil,
			fmt.Errorf("Could not unmarshal GetProposalReply: %v",
				err)
	}

	return &pr, nil
}

func (c *ctx) setPropStatus(id *identity.FullIdentity, token string, status v1.PropStatusT) (*v1.SetProposalStatusReply, error) {
	ps := v1.SetProposalStatus{
		Token:          token,
		ProposalStatus: status,
	}
	// Sign token+string(status)
	msg := []byte(ps.Token +
		strconv.FormatUint(uint64(ps.ProposalStatus), 10))
	var err error
	sig := id.SignMessage(msg)
	ps.Signature = hex.EncodeToString(sig[:])

	ps.PublicKey = hex.EncodeToString(id.Public.Key[:])

	responseBody, err := c.makeRequest("POST",
		"/proposals/"+token+"/status", /*v1.RouteSetProposalStatus*/
		ps)
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

func (c *ctx) changePassword(currentPassword, newPassword string) (*v1.ChangePasswordReply, error) {
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
		return nil, fmt.Errorf("Could not unmarshal "+
			"ChangePasswordReply: %v", err)
	}

	return &cpr, nil
}

func (c *ctx) resetPassword(email, password, newPassword string) error {
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

func (c *ctx) setNewKey(id *identity.FullIdentity) error {
	uuk := v1.UpdateUserKey{
		PublicKey: hex.EncodeToString(id.Public.Key[:]),
	}
	responseBody, err := c.makeRequest("POST", v1.RouteUpdateUserKey, uuk)
	if err != nil {
		return err
	}

	var uukr v1.UpdateUserKeyReply
	err = json.Unmarshal(responseBody, &uukr)
	if err != nil {
		return fmt.Errorf("Could not unmarshal UpdateUserKeyReply: %v", err)
	}

	sig := id.SignMessage([]byte(uukr.VerificationToken))
	vuuk := v1.VerifyUpdateUserKey{
		VerificationToken: uukr.VerificationToken,
		Signature:         hex.EncodeToString(sig[:]),
	}

	responseBody, err = c.makeRequest("POST", v1.RouteVerifyUpdateUserKey, vuuk)
	if err != nil {
		return err
	}

	var vuukr v1.VerifyUpdateUserKeyReply
	err = json.Unmarshal(responseBody, &vuukr)
	if err != nil {
		return fmt.Errorf("Could not unmarshal VerifyUpdateUserKeyReply: %v", err)
	}

	return nil
}

func (c *ctx) logout() error {
	l := v1.Logout{}
	_, err := c.makeRequest("GET", v1.RouteLogout, l)
	return err
}

func (c *ctx) assets() error {
	route := *host + "/static/" //v1.PoliteiaWWWAPIRoute + v1.RouteSecret
	fmt.Printf("asset Route : %v\n", route)
	req, err := http.NewRequest("GET", route, nil)
	if err != nil {
		return err
	}
	req.Header.Add(v1.CsrfToken, c.csrf)
	r, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		r.Body.Close()
	}()

	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP Status: %v", r.StatusCode)
	}

	_, err = io.Copy(os.Stdout, r.Body)
	return err
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
