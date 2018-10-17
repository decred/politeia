package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"

	"github.com/decred/dcrwallet/rpc/walletrpc"
	"github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/util"
	"github.com/gorilla/schema"
	"golang.org/x/net/publicsuffix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/decred/politeia/politeiawww/cmd/politeiawwwcli/config"
)

type Client struct {
	http *http.Client
	cfg  *config.Config

	// wallet grpc
	ctx    context.Context
	creds  credentials.TransportCredentials
	conn   *grpc.ClientConn
	wallet walletrpc.WalletServiceClient
}

func New(cfg *config.Config) (*Client, error) {
	// Create http client
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	// Set cookies
	jar, err := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(cfg.Host)
	if err != nil {
		return nil, err
	}
	jar.SetCookies(u, cfg.Cookies)
	httpClient := &http.Client{
		Transport: tr,
		Jar:       jar,
	}

	return &Client{
		http: httpClient,
		cfg:  cfg,
	}, nil
}

func (c *Client) makeRequest(method, route string, body interface{}) ([]byte, error) {
	// Setup request
	var requestBody []byte
	var queryParams string
	if body != nil {
		switch {
		case method == http.MethodGet:
			// GET requests don't have a request body; instead we
			// will populate the query params.
			form := url.Values{}
			if err := schema.NewEncoder().Encode(body, form); err != nil {
				return nil, err
			}
			queryParams = "?" + form.Encode()
		case method == http.MethodPost:
			var err error
			requestBody, err = json.Marshal(body)
			if err != nil {
				return nil, err
			}
		}
	}

	fullRoute := c.cfg.Host + v1.PoliteiaWWWAPIRoute + route + queryParams

	// Print request details
	switch {
	case c.cfg.Verbose && method == http.MethodGet:
		fmt.Printf("Request: GET %v\n", fullRoute)
	case c.cfg.Verbose && method == http.MethodPost:
		fmt.Printf("Request: POST %v\n", fullRoute)
		err := PrettyPrintJSON(body)
		if err != nil {
			return nil, err
		}
	}

	// Create http request
	req, err := http.NewRequest(method, fullRoute, bytes.NewReader(requestBody))
	if err != nil {
		return nil, err
	}
	req.Header.Add(v1.CsrfToken, c.cfg.CSRF)

	// Send request
	r, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		r.Body.Close()
	}()

	responseBody := util.ConvertBodyToByteArray(r.Body, false)

	// Validate response status
	if r.StatusCode != http.StatusOK {
		var ue v1.UserError
		err = json.Unmarshal(responseBody, &ue)
		if err == nil {
			return nil, fmt.Errorf("%v, %v %v", r.StatusCode,
				v1.ErrorStatus[ue.ErrorCode], strings.Join(ue.ErrorContext, ", "))
		}

		return nil, fmt.Errorf("%v", r.StatusCode)
	}

	// Print response details
	if c.cfg.Verbose {
		fmt.Printf("Response: %v\n", r.StatusCode)
	}

	return responseBody, nil
}

func (c *Client) Version() (*v1.VersionReply, error) {
	fullRoute := c.cfg.Host + v1.PoliteiaWWWAPIRoute + v1.RouteVersion

	// Print request details
	if c.cfg.Verbose {
		fmt.Printf("Request: GET %v\n", fullRoute)
	}

	// Create new http request instead of using makeRequest()
	// so that we can save the CSRF tokens to disk.
	req, err := http.NewRequest("GET", fullRoute, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add(v1.CsrfToken, c.cfg.CSRF)

	// Send request
	r, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		r.Body.Close()
	}()

	responseBody := util.ConvertBodyToByteArray(r.Body, false)

	// Validate response status
	if r.StatusCode != http.StatusOK {
		var ue v1.UserError
		err = json.Unmarshal(responseBody, &ue)
		if err == nil {
			return nil, fmt.Errorf("%v, %v %v", r.StatusCode,
				v1.ErrorStatus[ue.ErrorCode], strings.Join(ue.ErrorContext, ", "))
		}

		return nil, fmt.Errorf("%v", r.StatusCode)
	}

	// Unmarshal response
	var vr v1.VersionReply
	err = json.Unmarshal(responseBody, &vr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal VersionReply: %v", err)
	}

	// Print response details
	if c.cfg.Verbose {
		fmt.Printf("Response: %v\n", r.StatusCode)
		err := PrettyPrintJSON(vr)
		if err != nil {
			return nil, err
		}
	}

	// CSRF protection works via the double-submit method.
	// One token is sent in the cookie. A second token is
	// sent in the header. Both tokens must be persisted
	// between CLI commands.

	// Persist CSRF header token
	c.cfg.CSRF = r.Header.Get(v1.CsrfToken)
	err = c.cfg.SaveCSRF(c.cfg.CSRF)
	if err != nil {
		return nil, err
	}

	// Persist CSRF cookie token
	err = c.cfg.SaveCookies(c.http.Jar.Cookies(req.URL))
	if err != nil {
		return nil, err
	}

	return &vr, nil
}

func (c *Client) Login(l *v1.Login) (*v1.LoginReply, error) {
	// Setup request
	requestBody, err := json.Marshal(l)
	if err != nil {
		return nil, err
	}

	fullRoute := c.cfg.Host + v1.PoliteiaWWWAPIRoute + v1.RouteLogin

	// Print request details
	if c.cfg.Verbose {
		fmt.Printf("Request: POST %v\n", fullRoute)
		err := PrettyPrintJSON(l)
		if err != nil {
			return nil, err
		}
	}

	// Create new http request instead of using makeRequest()
	// so that we can save the session data for subsequent
	// commands
	req, err := http.NewRequest("POST", fullRoute, bytes.NewReader(requestBody))
	if err != nil {
		return nil, err
	}
	req.Header.Add(v1.CsrfToken, c.cfg.CSRF)

	// Send request
	r, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		r.Body.Close()
	}()

	responseBody := util.ConvertBodyToByteArray(r.Body, false)

	// Validate response status
	if r.StatusCode != http.StatusOK {
		var ue v1.UserError
		err = json.Unmarshal(responseBody, &ue)
		if err == nil {
			return nil, fmt.Errorf("%v, %v %v", r.StatusCode,
				v1.ErrorStatus[ue.ErrorCode], strings.Join(ue.ErrorContext, ", "))
		}

		return nil, fmt.Errorf("%v", r.StatusCode)
	}

	// Unmarshal response
	var lr v1.LoginReply
	err = json.Unmarshal(responseBody, &lr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal LoginReply: %v", err)
	}

	// Print response details
	if c.cfg.Verbose {
		fmt.Printf("Response: %v\n", r.StatusCode)
		err := PrettyPrintJSON(lr)
		if err != nil {
			return nil, err
		}
	}

	// Persist session data
	ck := c.http.Jar.Cookies(req.URL)
	if err = c.cfg.SaveCookies(ck); err != nil {
		return nil, err
	}

	return &lr, nil
}

func (c *Client) Logout() (*v1.LogoutReply, error) {
	fullRoute := c.cfg.Host + v1.PoliteiaWWWAPIRoute + v1.RouteLogout

	// Print request details
	if c.cfg.Verbose {
		fmt.Printf("Request: GET  %v\n", fullRoute)
	}

	// Create new http request instead of using makeRequest()
	// so that we can save the updated cookies to disk
	req, err := http.NewRequest("GET", fullRoute, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add(v1.CsrfToken, c.cfg.CSRF)

	// Send request
	r, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		r.Body.Close()
	}()

	responseBody := util.ConvertBodyToByteArray(r.Body, false)

	// Validate response status
	if r.StatusCode != http.StatusOK {
		var ue v1.UserError
		err = json.Unmarshal(responseBody, &ue)
		if err == nil {
			return nil, fmt.Errorf("%v, %v %v", r.StatusCode,
				v1.ErrorStatus[ue.ErrorCode], strings.Join(ue.ErrorContext, ", "))
		}

		return nil, fmt.Errorf("%v", r.StatusCode)
	}

	// Unmarshal response
	var lr v1.LogoutReply
	err = json.Unmarshal(responseBody, &lr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal LogoutReply: %v", err)
	}

	// Print response details
	if c.cfg.Verbose {
		fmt.Printf("Response: %v\n", r.StatusCode)
		err := PrettyPrintJSON(lr)
		if err != nil {
			return nil, err
		}
	}

	// Persist cookies
	ck := c.http.Jar.Cookies(req.URL)
	if err = c.cfg.SaveCookies(ck); err != nil {
		return nil, err
	}

	return &lr, nil
}

func (c *Client) Policy() (*v1.PolicyReply, error) {
	responseBody, err := c.makeRequest("GET", v1.RoutePolicy, nil)
	if err != nil {
		return nil, err
	}

	var pr v1.PolicyReply
	err = json.Unmarshal(responseBody, &pr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal PolicyReply: %v", err)
	}

	if c.cfg.Verbose {
		err := PrettyPrintJSON(pr)
		if err != nil {
			return nil, err
		}
	}

	return &pr, nil
}

func (c *Client) NewUser(nu *v1.NewUser) (*v1.NewUserReply, error) {
	responseBody, err := c.makeRequest("POST", v1.RouteNewUser, nu)
	if err != nil {
		return nil, err
	}

	var nur v1.NewUserReply
	err = json.Unmarshal(responseBody, &nur)
	if err != nil {
		return nil, fmt.Errorf("unmarshal NewUserReply: %v", err)
	}

	if c.cfg.Verbose {
		err := PrettyPrintJSON(nur)
		if err != nil {
			return nil, err
		}
	}

	return &nur, nil
}

func (c *Client) VerifyNewUser(vnu *v1.VerifyNewUser) (*v1.VerifyNewUserReply, error) {
	responseBody, err := c.makeRequest("GET", "/user/verify", vnu)
	if err != nil {
		return nil, err
	}

	var vnur v1.VerifyNewUserReply
	err = json.Unmarshal(responseBody, &vnur)
	if err != nil {
		return nil, fmt.Errorf("unmarshal VerifyNewUserReply: %v", err)
	}

	if c.cfg.Verbose {
		err := PrettyPrintJSON(vnur)
		if err != nil {
			return nil, err
		}
	}

	return &vnur, nil
}

func (c *Client) Me() (*v1.LoginReply, error) {
	responseBody, err := c.makeRequest("GET", v1.RouteUserMe, nil)
	if err != nil {
		return nil, err
	}

	var lr v1.LoginReply
	err = json.Unmarshal(responseBody, &lr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal LoginReply: %v", err)
	}

	if c.cfg.Verbose {
		err := PrettyPrintJSON(lr)
		if err != nil {
			return nil, err
		}
	}

	return &lr, nil
}

func (c *Client) Secret() (*v1.UserError, error) {
	responseBody, err := c.makeRequest("POST", v1.RouteSecret, v1.Login{})
	if err != nil {
		return nil, err
	}

	var ue v1.UserError
	err = json.Unmarshal(responseBody, &ue)
	if err != nil {
		return nil, fmt.Errorf("unmarshal UserError: %v", err)
	}

	if c.cfg.Verbose {
		err := PrettyPrintJSON(ue)
		if err != nil {
			return nil, err
		}
	}

	return &ue, nil
}

func (c *Client) ChangeUsername(cu *v1.ChangeUsername) (*v1.ChangeUsernameReply, error) {
	responseBody, err := c.makeRequest("POST", v1.RouteChangeUsername, cu)
	if err != nil {
		return nil, err
	}

	var cur v1.ChangeUsernameReply
	err = json.Unmarshal(responseBody, &cur)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ChangeUsernameReply: %v", err)
	}

	if c.cfg.Verbose {
		err := PrettyPrintJSON(cur)
		if err != nil {
			return nil, err
		}
	}

	return &cur, nil
}

func (c *Client) ChangePassword(cp *v1.ChangePassword) (*v1.ChangePasswordReply, error) {
	responseBody, err := c.makeRequest("POST", v1.RouteChangePassword, cp)
	if err != nil {
		return nil, err
	}

	var cpr v1.ChangePasswordReply
	err = json.Unmarshal(responseBody, &cpr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ChangePasswordReply: %v", err)
	}

	if c.cfg.Verbose {
		err := PrettyPrintJSON(cpr)
		if err != nil {
			return nil, err
		}
	}

	return &cpr, nil
}

func (c *Client) ResetPassword(rp *v1.ResetPassword) (*v1.ResetPasswordReply, error) {
	responseBody, err := c.makeRequest("POST", v1.RouteResetPassword, rp)
	if err != nil {
		return nil, err
	}

	var rpr v1.ResetPasswordReply
	err = json.Unmarshal(responseBody, &rpr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ResetPasswordReply: %v", err)
	}

	if c.cfg.Verbose {
		err := PrettyPrintJSON(rpr)
		if err != nil {
			return nil, err
		}
	}

	return &rpr, nil
}

func (c *Client) ProposalPaywallDetails(ppd *v1.ProposalPaywallDetails) (*v1.ProposalPaywallDetailsReply, error) {
	responseBody, err := c.makeRequest("GET", v1.RouteProposalPaywallDetails,
		ppd)
	if err != nil {
		return nil, err
	}

	var ppdr v1.ProposalPaywallDetailsReply
	err = json.Unmarshal(responseBody, &ppdr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ProposalPaywalDetailsReply: %v", err)
	}

	if c.cfg.Verbose {
		err := PrettyPrintJSON(ppdr)
		if err != nil {
			return nil, err
		}
	}

	return &ppdr, nil
}

func (c *Client) NewProposal(np *v1.NewProposal) (*v1.NewProposalReply, error) {
	responseBody, err := c.makeRequest("POST", v1.RouteNewProposal, np)
	if err != nil {
		return nil, err
	}

	var npr v1.NewProposalReply
	err = json.Unmarshal(responseBody, &npr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal NewProposalReply: %v", err)
	}

	if c.cfg.Verbose {
		err := PrettyPrintJSON(npr)
		if err != nil {
			return nil, err
		}
	}

	return &npr, nil
}

func (c *Client) EditProposal(ep *v1.EditProposal) (*v1.EditProposalReply, error) {
	responseBody, err := c.makeRequest("POST", v1.RouteEditProposal, ep)
	if err != nil {
		return nil, err
	}

	var epr v1.EditProposalReply
	err = json.Unmarshal(responseBody, &epr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal EditProposalReply: %v", err)
	}

	if c.cfg.Verbose {
		err := PrettyPrintJSON(epr)
		if err != nil {
			return nil, err
		}
	}

	return &epr, nil
}

func (c *Client) ProposalDetails(token string) (*v1.ProposalDetailsReply, error) {
	responseBody, err := c.makeRequest("GET", "/proposals/"+token, nil)
	if err != nil {
		return nil, err
	}

	var pr v1.ProposalDetailsReply
	err = json.Unmarshal(responseBody, &pr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ProposalDetailsReply: %v", err)
	}

	if c.cfg.Verbose {
		err := PrettyPrintJSON(pr)
		if err != nil {
			return nil, err
		}
	}

	return &pr, nil
}

func (c *Client) UserProposals(up *v1.UserProposals) (*v1.UserProposalsReply, error) {
	responseBody, err := c.makeRequest("GET", v1.RouteUserProposals, up)
	if err != nil {
		return nil, err
	}

	var upr v1.UserProposalsReply
	err = json.Unmarshal(responseBody, &upr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal UserProposalsReply: %v", err)
	}

	if c.cfg.Verbose {
		err := PrettyPrintJSON(upr)
		if err != nil {
			return nil, err
		}
	}

	return &upr, nil
}

func (c *Client) SetProposalStatus(sps *v1.SetProposalStatus) (*v1.SetProposalStatusReply, error) {
	route := "/proposals/" + sps.Token + "/status"
	responseBody, err := c.makeRequest("POST", route, sps)
	if err != nil {
		return nil, err
	}

	var spsr v1.SetProposalStatusReply
	err = json.Unmarshal(responseBody, &spsr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal SetProposalStatusReply: %v", err)
	}

	if c.cfg.Verbose {
		err := PrettyPrintJSON(spsr)
		if err != nil {
			return nil, err
		}
	}

	return &spsr, nil
}

func (c *Client) GetAllVetted(gav *v1.GetAllVetted) (*v1.GetAllVettedReply, error) {
	responseBody, err := c.makeRequest("GET", v1.RouteAllVetted, gav)
	if err != nil {
		return nil, err
	}

	var gavr v1.GetAllVettedReply
	err = json.Unmarshal(responseBody, &gavr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal GetAllVettedReply: %v", err)
	}

	if c.cfg.Verbose {
		err := PrettyPrintJSON(gavr)
		if err != nil {
			return nil, err
		}
	}

	return &gavr, nil
}

func (c *Client) GetAllUnvetted(gau *v1.GetAllUnvetted) (*v1.GetAllUnvettedReply, error) {
	responseBody, err := c.makeRequest("GET", v1.RouteAllUnvetted, gau)
	if err != nil {
		return nil, err
	}

	var gaur v1.GetAllUnvettedReply
	err = json.Unmarshal(responseBody, &gaur)
	if err != nil {
		return nil, fmt.Errorf("unmarshal GetAllUnvettedReply: %v", err)
	}

	if c.cfg.Verbose {
		err := PrettyPrintJSON(gaur)
		if err != nil {
			return nil, err
		}
	}

	return &gaur, nil
}

func (c *Client) NewComment(nc *v1.NewComment) (*v1.NewCommentReply, error) {
	responseBody, err := c.makeRequest("POST", v1.RouteNewComment, nc)
	if err != nil {
		return nil, err
	}

	var ncr v1.NewCommentReply
	err = json.Unmarshal(responseBody, &ncr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal NewCommentReply: %v", err)
	}

	if c.cfg.Verbose {
		err := PrettyPrintJSON(ncr)
		if err != nil {
			return nil, err
		}
	}

	return &ncr, nil
}

func (c *Client) GetComments(token string) (*v1.GetCommentsReply, error) {
	responseBody, err := c.makeRequest("GET", "/proposals/"+token+"/comments",
		nil)
	if err != nil {
		return nil, err
	}

	var gcr v1.GetCommentsReply
	err = json.Unmarshal(responseBody, &gcr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal GetCommentsReply: %v", err)
	}

	if c.cfg.Verbose {
		err := PrettyPrintJSON(gcr)
		if err != nil {
			return nil, err
		}
	}

	return &gcr, nil
}

func (c *Client) UserCommentsVotes(token string) (*v1.UserCommentsVotesReply, error) {
	route := "/user/proposals/" + token + "/commentsvotes"
	responseBody, err := c.makeRequest("GET", route, nil)
	if err != nil {
		return nil, err
	}

	var ucvr v1.UserCommentsVotesReply
	err = json.Unmarshal(responseBody, &ucvr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal UserCommentsVotesReply: %v", err)
	}

	if c.cfg.Verbose {
		err := PrettyPrintJSON(ucvr)
		if err != nil {
			return nil, err
		}
	}

	return &ucvr, nil
}

func (c *Client) LikeComment(lc *v1.LikeComment) (*v1.LikeCommentReply, error) {
	responseBody, err := c.makeRequest("POST", v1.RouteLikeComment, lc)
	if err != nil {
		return nil, err
	}

	var lcr v1.LikeCommentReply
	err = json.Unmarshal(responseBody, &lcr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal LikeCommentReply: %v", err)
	}

	if c.cfg.Verbose {
		err := PrettyPrintJSON(lcr)
		if err != nil {
			return nil, err
		}
	}

	return &lcr, nil
}

func (c *Client) CensorComment(cc *v1.CensorComment) (*v1.CensorCommentReply, error) {
	responseBody, err := c.makeRequest("POST", v1.RouteCensorComment, cc)
	if err != nil {
		return nil, err
	}

	var ccr v1.CensorCommentReply
	err = json.Unmarshal(responseBody, &ccr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal CensorCommentReply: %v", err)
	}

	if c.cfg.Verbose {
		err := PrettyPrintJSON(ccr)
		if err != nil {
			return nil, err
		}
	}

	return &ccr, nil
}

func (c *Client) StartVote(sv *v1.StartVote) (*v1.StartVoteReply, error) {
	responseBody, err := c.makeRequest("POST", v1.RouteStartVote, sv)
	if err != nil {
		return nil, err
	}

	var svr v1.StartVoteReply
	err = json.Unmarshal(responseBody, &svr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal StartVoteReply: %v", err)
	}

	if c.cfg.Verbose {
		err := PrettyPrintJSON(svr)
		if err != nil {
			return nil, err
		}
	}

	return &svr, nil
}

func (c *Client) VerifyUserPayment() (*v1.VerifyUserPaymentReply, error) {
	responseBody, err := c.makeRequest("GET", v1.RouteVerifyUserPayment, nil)
	if err != nil {
		return nil, err
	}

	var vupr v1.VerifyUserPaymentReply
	err = json.Unmarshal(responseBody, &vupr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal VerifyUserPaymentReply: %v", err)
	}

	if c.cfg.Verbose {
		err := PrettyPrintJSON(vupr)
		if err != nil {
			return nil, err
		}
	}

	return &vupr, nil
}

func (c *Client) UsernamesByID(ubi *v1.UsernamesById) (*v1.UsernamesByIdReply, error) {
	responseBody, err := c.makeRequest("POST", v1.RouteUsernamesById, ubi)
	if err != nil {
		return nil, err
	}

	var ubir v1.UsernamesByIdReply
	err = json.Unmarshal(responseBody, &ubir)
	if err != nil {
		return nil, fmt.Errorf("unmarshal UsernamesByIdReply: %v", err)
	}

	if c.cfg.Verbose {
		err := PrettyPrintJSON(ubir)
		if err != nil {
			return nil, err
		}
	}

	return &ubir, nil
}

func (c *Client) ProposalVotes(token string) (*v1.VoteResultsReply, error) {
	responseBody, err := c.makeRequest("GET", "/proposals/"+token+"/votes", nil)
	if err != nil {
		return nil, err
	}

	var vrr v1.VoteResultsReply
	err = json.Unmarshal(responseBody, &vrr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ProposalVotesReply: %v", err)
	}

	if c.cfg.Verbose {
		err := PrettyPrintJSON(vrr)
		if err != nil {
			return nil, err
		}
	}

	return &vrr, nil
}

func (c *Client) UserDetails(userID string) (*v1.UserDetailsReply, error) {
	responseBody, err := c.makeRequest("GET", "/user/"+userID, nil)
	if err != nil {
		return nil, err
	}

	var udr v1.UserDetailsReply
	err = json.Unmarshal(responseBody, &udr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal UserDetailsReply: %v", err)
	}

	if c.cfg.Verbose {
		err := PrettyPrintJSON(udr)
		if err != nil {
			return nil, err
		}
	}

	return &udr, nil
}

func (c *Client) Users(u *v1.Users) (*v1.UsersReply, error) {
	responseBody, err := c.makeRequest("GET", v1.RouteUsers, u)
	if err != nil {
		return nil, err
	}

	var ur v1.UsersReply
	err = json.Unmarshal(responseBody, &ur)
	if err != nil {
		return nil, fmt.Errorf("unmarshal UsersReply: %v", err)
	}

	if c.cfg.Verbose {
		err := PrettyPrintJSON(ur)
		if err != nil {
			return nil, err
		}
	}

	return &ur, nil
}

func (c *Client) EditUser(eu *v1.EditUser) (*v1.EditUserReply, error) {
	responseBody, err := c.makeRequest("POST", v1.RouteEditUser, eu)
	if err != nil {
		return nil, err
	}

	var eur v1.EditUserReply
	err = json.Unmarshal(responseBody, &eur)
	if err != nil {
		return nil, fmt.Errorf("unmarshal EditUserReply: %v", err)
	}

	if c.cfg.Verbose {
		err := PrettyPrintJSON(eur)
		if err != nil {
			return nil, err
		}
	}

	return &eur, nil
}

func (c *Client) AuthorizeVote(av *v1.AuthorizeVote) (*v1.AuthorizeVoteReply, error) {
	responseBody, err := c.makeRequest("POST", "/proposals/authorizevote", av)
	if err != nil {
		return nil, err
	}

	var avr v1.AuthorizeVoteReply
	err = json.Unmarshal(responseBody, &avr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal AuthorizeVoteReply: %v", err)
	}

	if c.cfg.Verbose {
		err := PrettyPrintJSON(avr)
		if err != nil {
			return nil, err
		}
	}

	return &avr, nil
}

func (c *Client) VoteStatus(token string) (*v1.VoteStatusReply, error) {
	route := "/proposals/" + token + "/votestatus"
	responseBody, err := c.makeRequest("GET", route, nil)
	if err != nil {
		return nil, err
	}

	var vsr v1.VoteStatusReply
	err = json.Unmarshal(responseBody, &vsr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal VoteStatusReply: %v", err)
	}

	if c.cfg.Verbose {
		err := PrettyPrintJSON(vsr)
		if err != nil {
			return nil, err
		}
	}

	return &vsr, nil
}

func (c *Client) ActiveVotes() (*v1.ActiveVoteReply, error) {
	responseBody, err := c.makeRequest("GET", v1.RouteActiveVote, nil)
	if err != nil {
		return nil, err
	}

	var avr v1.ActiveVoteReply
	err = json.Unmarshal(responseBody, &avr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ActiveVoteReply: %v", err)
	}

	if c.cfg.Verbose {
		err := PrettyPrintJSON(avr)
		if err != nil {
			return nil, err
		}
	}

	return &avr, nil
}

func (c *Client) CastVotes(b *v1.Ballot) (*v1.BallotReply, error) {
	responseBody, err := c.makeRequest("POST", v1.RouteCastVotes, &b)
	if err != nil {
		return nil, err
	}

	var br v1.BallotReply
	err = json.Unmarshal(responseBody, &br)
	if err != nil {
		return nil, fmt.Errorf("unmarshal BallotReply: %v", err)
	}

	if c.cfg.Verbose {
		err := PrettyPrintJSON(br)
		if err != nil {
			return nil, err
		}
	}

	return &br, nil
}

func (c *Client) UpdateUserKey(uuk *v1.UpdateUserKey) (*v1.UpdateUserKeyReply, error) {
	responseBody, err := c.makeRequest("POST", v1.RouteUpdateUserKey, &uuk)
	if err != nil {
		return nil, err
	}

	var uukr v1.UpdateUserKeyReply
	err = json.Unmarshal(responseBody, &uukr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal UpdateUserKeyReply: %v", err)
	}

	if c.cfg.Verbose {
		err := PrettyPrintJSON(uukr)
		if err != nil {
			return nil, err
		}
	}

	return &uukr, nil
}

func (c *Client) VerifyUpdateUserKey(vuuk *v1.VerifyUpdateUserKey) (*v1.VerifyUpdateUserKeyReply, error) {
	responseBody, err := c.makeRequest("POST", v1.RouteVerifyUpdateUserKey,
		&vuuk)
	if err != nil {
		return nil, err
	}

	var vuukr v1.VerifyUpdateUserKeyReply
	err = json.Unmarshal(responseBody, &vuukr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal VerifyUpdateUserKeyReply: %v", err)
	}

	if c.cfg.Verbose {
		err := PrettyPrintJSON(vuukr)
		if err != nil {
			return nil, err
		}
	}

	return &vuukr, nil
}

func (c *Client) ProposalPaywallPayment() (*v1.ProposalPaywallPaymentReply, error) {
	responseBody, err := c.makeRequest("GET",
		v1.RouteProposalPaywallPayment, nil)
	if err != nil {
		return nil, err
	}

	var pppr v1.ProposalPaywallPaymentReply
	err = json.Unmarshal(responseBody, &pppr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ProposalPaywallPaymentReply: %v", err)
	}

	if c.cfg.Verbose {
		err := PrettyPrintJSON(pppr)
		if err != nil {
			return nil, err
		}
	}

	return &pppr, nil
}
