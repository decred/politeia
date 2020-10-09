// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package shared

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"reflect"
	"strings"

	"decred.org/dcrwallet/rpc/walletrpc"
	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	pi "github.com/decred/politeia/politeiawww/api/pi/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	www2 "github.com/decred/politeia/politeiawww/api/www/v2"
	"github.com/decred/politeia/util"
	"github.com/gorilla/schema"
	"golang.org/x/net/publicsuffix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Client is a politeiawww client.
type Client struct {
	http *http.Client
	cfg  *Config

	// wallet grpc
	ctx    context.Context
	creds  credentials.TransportCredentials
	conn   *grpc.ClientConn
	wallet walletrpc.WalletServiceClient
}

func prettyPrintJSON(v interface{}) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("MarshalIndent: %v", err)
	}
	fmt.Fprintf(os.Stdout, "%s\n", b)
	return nil
}

// userWWWErrorStatus retrieves the human readable error message for an error
// status code. The status code error message comes from the www api.
func userWWWErrorStatus(e www.ErrorStatusT) string {
	s, ok := www.ErrorStatus[e]
	if ok {
		return s
	}
	s, ok = cms.ErrorStatus[e]
	if ok {
		return s
	}
	return ""
}

// userPiErrorStatus retrieves the human readable error message for an error
// status code. The status code error message comes from the pi api.
func userPiErrorStatus(e pi.ErrorStatusT) string {
	s, ok := pi.ErrorStatus[e]
	if ok {
		return s
	}
	return ""
}

// wwwError unmarshals the response body from makeRequest, and parses
// the error code and error context from the www api.
func wwwError(body []byte, statusCode int) error {
	var ue www.UserError
	err := json.Unmarshal(body, &ue)
	if err != nil {
		return fmt.Errorf("unmarshal UserError: %v", err)
	}
	if ue.ErrorCode != 0 {
		var e error
		errMsg := userWWWErrorStatus(ue.ErrorCode)
		if len(ue.ErrorContext) == 0 {
			// Error format when an ErrorContext is not included
			e = fmt.Errorf("%v, %v", statusCode, errMsg)
		} else {
			// Error format when an ErrorContext is included
			e = fmt.Errorf("%v, %v: %v", statusCode, errMsg,
				strings.Join(ue.ErrorContext, ", "))
		}
		return e
	}
	return nil
}

// piError unmarshals the response body from makeRequest, and parses
// the error code and error context from the pi api.
func piError(body []byte, statusCode int) error {
	var ue pi.UserErrorReply
	err := json.Unmarshal(body, &ue)
	if err != nil {
		return fmt.Errorf("unmarshal UserError: %v", err)
	}
	if ue.ErrorCode != 0 {
		var e error
		errMsg := userPiErrorStatus(ue.ErrorCode)
		if len(ue.ErrorContext) == 0 {
			// Error format when an ErrorContext is not included
			e = fmt.Errorf("%v, %v", statusCode, errMsg)
		} else {
			// Error format when an ErrorContext is included
			e = fmt.Errorf("%v, %v: %v", statusCode, errMsg,
				strings.Join(ue.ErrorContext, ", "))
		}
		return e
	}
	return nil
}

// makeRequest sends the provided request to the politeiawww backend specified
// by the Client config. This function handles verbose printing when specified
// by the Client config since verbose printing includes details such as the
// full route and http response codes. Caller functions handle status code
// validation and error checks.
func (c *Client) makeRequest(method, routeVersion, route string, body interface{}) (int, []byte, error) {
	// Setup request
	var requestBody []byte
	var queryParams string
	if body != nil {
		switch {
		case method == http.MethodGet:
			// Use reflection in case the interface value is nil
			// but the interface type is not. This can happen when
			// query params exist but are not used.
			if reflect.ValueOf(body).IsNil() {
				break
			}

			// GET requests don't have a request body; instead we
			// will populate the query params.
			form := url.Values{}
			if err := schema.NewEncoder().Encode(body, form); err != nil {
				return 0, nil, err
			}
			queryParams = "?" + form.Encode()

		case method == http.MethodPost || method == http.MethodPut:
			var err error
			requestBody, err = json.Marshal(body)
			if err != nil {
				return 0, nil, err
			}

		default:
			return 0, nil, fmt.Errorf("unknown http method '%v'", method)
		}
	}

	fullRoute := c.cfg.Host + routeVersion + route + queryParams

	// Print request details
	switch {
	case c.cfg.Verbose && method == http.MethodGet:
		fmt.Printf("Request: GET %v\n", fullRoute)
	case c.cfg.Verbose && method == http.MethodPost:
		fmt.Printf("Request: POST %v\n", fullRoute)
		err := prettyPrintJSON(body)
		if err != nil {
			return 0, nil, err
		}
	case c.cfg.Verbose && method == http.MethodPut:
		fmt.Printf("Request: PUT %v\n", fullRoute)
		err := prettyPrintJSON(body)
		if err != nil {
			return 0, nil, err
		}
	}

	// Create http request
	req, err := http.NewRequest(method, fullRoute, bytes.NewReader(requestBody))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Add(www.CsrfToken, c.cfg.CSRF)

	// Send request
	r, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() {
		r.Body.Close()
	}()

	responseBody := util.ConvertBodyToByteArray(r.Body, false)

	// Print response details
	if c.cfg.Verbose {
		fmt.Printf("Response: %v\n", r.StatusCode)
	}

	return r.StatusCode, responseBody, nil
}

// Version returns the version information for the politeiawww instance.
func (c *Client) Version() (*www.VersionReply, error) {
	fullRoute := c.cfg.Host + www.PoliteiaWWWAPIRoute + www.RouteVersion

	// Print request details
	if c.cfg.Verbose {
		fmt.Printf("Request: GET %v\n", fullRoute)
	}

	// Create new http request instead of using makeRequest()
	// so that we can save the CSRF tokens to disk.
	req, err := http.NewRequest(http.MethodGet, fullRoute, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add(www.CsrfToken, c.cfg.CSRF)

	// Send request
	r, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		r.Body.Close()
	}()

	respBody := util.ConvertBodyToByteArray(r.Body, false)

	// Validate response status
	if r.StatusCode != http.StatusOK {
		var ue www.UserError
		err = json.Unmarshal(respBody, &ue)
		if err == nil {
			return nil, fmt.Errorf("%v, %v %v", r.StatusCode,
				userWWWErrorStatus(ue.ErrorCode),
				strings.Join(ue.ErrorContext, ", "))
		}

		return nil, fmt.Errorf("%v", r.StatusCode)
	}

	// Unmarshal response
	var vr www.VersionReply
	err = json.Unmarshal(respBody, &vr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal VersionReply: %v", err)
	}

	// Print response details
	if c.cfg.Verbose {
		fmt.Printf("Response: %v\n", r.StatusCode)
		err := prettyPrintJSON(vr)
		if err != nil {
			return nil, err
		}
	}

	// CSRF protection works via the double-submit method.
	// One token is sent in the cookie. A second token is
	// sent in the header. Both tokens must be persisted
	// between CLI commands.

	// Persist CSRF header token
	c.cfg.CSRF = r.Header.Get(www.CsrfToken)
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

// Login logs a user into politeiawww.
func (c *Client) Login(l *www.Login) (*www.LoginReply, error) {
	// Setup request
	requestBody, err := json.Marshal(l)
	if err != nil {
		return nil, err
	}

	fullRoute := c.cfg.Host + www.PoliteiaWWWAPIRoute + www.RouteLogin

	// Print request details
	if c.cfg.Verbose {
		fmt.Printf("Request: POST %v\n", fullRoute)
		err := prettyPrintJSON(l)
		if err != nil {
			return nil, err
		}
	}

	// Create new http request instead of using makeRequest()
	// so that we can save the session data for subsequent
	// commands
	req, err := http.NewRequest(http.MethodPost, fullRoute,
		bytes.NewReader(requestBody))
	if err != nil {
		return nil, err
	}
	req.Header.Add(www.CsrfToken, c.cfg.CSRF)

	// Send request
	r, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		r.Body.Close()
	}()

	respBody := util.ConvertBodyToByteArray(r.Body, false)

	// Validate response status
	if r.StatusCode != http.StatusOK {
		var ue www.UserError
		err = json.Unmarshal(respBody, &ue)
		if err == nil {
			return nil, fmt.Errorf("%v, %v %v", r.StatusCode,
				userWWWErrorStatus(ue.ErrorCode),
				strings.Join(ue.ErrorContext, ", "))
		}

		return nil, fmt.Errorf("%v", r.StatusCode)
	}

	// Unmarshal response
	var lr www.LoginReply
	err = json.Unmarshal(respBody, &lr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal LoginReply: %v", err)
	}

	// Print response details
	if c.cfg.Verbose {
		fmt.Printf("Response: %v\n", r.StatusCode)
		err := prettyPrintJSON(lr)
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

// Logout logs out a user from politeiawww.
func (c *Client) Logout() (*www.LogoutReply, error) {
	fullRoute := c.cfg.Host + www.PoliteiaWWWAPIRoute + www.RouteLogout

	// Print request details
	if c.cfg.Verbose {
		fmt.Printf("Request: POST  %v\n", fullRoute)
	}

	// Create new http request instead of using makeRequest()
	// so that we can save the updated cookies to disk
	req, err := http.NewRequest(http.MethodPost, fullRoute, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add(www.CsrfToken, c.cfg.CSRF)

	// Send request
	r, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		r.Body.Close()
	}()

	respBody := util.ConvertBodyToByteArray(r.Body, false)

	// Validate response status
	if r.StatusCode != http.StatusOK {
		var ue www.UserError
		err = json.Unmarshal(respBody, &ue)
		if err == nil {
			return nil, fmt.Errorf("%v, %v %v", r.StatusCode,
				userWWWErrorStatus(ue.ErrorCode),
				strings.Join(ue.ErrorContext, ", "))
		}

		return nil, fmt.Errorf("%v", r.StatusCode)
	}

	// Unmarshal response
	var lr www.LogoutReply
	err = json.Unmarshal(respBody, &lr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal LogoutReply: %v", err)
	}

	// Print response details
	if c.cfg.Verbose {
		fmt.Printf("Response: %v\n", r.StatusCode)
		err := prettyPrintJSON(lr)
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

// Policy returns the politeiawww policy information.
func (c *Client) Policy() (*www.PolicyReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodGet,
		www.PoliteiaWWWAPIRoute, www.RoutePolicy, nil)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var pr www.PolicyReply
	err = json.Unmarshal(respBody, &pr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal PolicyReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(pr)
		if err != nil {
			return nil, err
		}
	}

	return &pr, nil
}

// CMSPolicy returns the politeiawww policy information.
func (c *Client) CMSPolicy() (*cms.PolicyReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodGet,
		www.PoliteiaWWWAPIRoute, www.RoutePolicy, nil)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var pr cms.PolicyReply
	err = json.Unmarshal(respBody, &pr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal CMSPolicyReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(pr)
		if err != nil {
			return nil, err
		}
	}

	return &pr, nil
}

// InviteNewUser creates a new cmswww user.
func (c *Client) InviteNewUser(inu *cms.InviteNewUser) (*cms.InviteNewUserReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		cms.APIRoute, cms.RouteInviteNewUser, inu)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var inur cms.InviteNewUserReply
	err = json.Unmarshal(respBody, &inur)
	if err != nil {
		return nil, fmt.Errorf("unmarshal InviteNewUserReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(inur)
		if err != nil {
			return nil, err
		}
	}

	return &inur, nil
}

// RegisterUser finalizes the signup process for a new cmswww user.
func (c *Client) RegisterUser(ru *cms.RegisterUser) (*cms.RegisterUserReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		cms.APIRoute, cms.RouteRegisterUser, ru)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var rur cms.RegisterUserReply
	err = json.Unmarshal(respBody, &rur)
	if err != nil {
		return nil, fmt.Errorf("unmarshal RegisterUserReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(rur)
		if err != nil {
			return nil, err
		}
	}

	return &rur, nil
}

// NewUser creates a new politeiawww user.
func (c *Client) NewUser(nu *www.NewUser) (*www.NewUserReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		www.PoliteiaWWWAPIRoute, www.RouteNewUser, nu)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var nur www.NewUserReply
	err = json.Unmarshal(respBody, &nur)
	if err != nil {
		return nil, fmt.Errorf("unmarshal NewUserReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(nur)
		if err != nil {
			return nil, err
		}
	}

	return &nur, nil
}

// VerifyNewUser verifies a user's email address.
func (c *Client) VerifyNewUser(vnu *www.VerifyNewUser) (*www.VerifyNewUserReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodGet,
		www.PoliteiaWWWAPIRoute, www.RouteVerifyNewUser, vnu)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var vnur www.VerifyNewUserReply
	err = json.Unmarshal(respBody, &vnur)
	if err != nil {
		return nil, fmt.Errorf("unmarshal VerifyNewUserReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(vnur)
		if err != nil {
			return nil, err
		}
	}

	return &vnur, nil
}

// Me returns user details for the logged in user.
func (c *Client) Me() (*www.LoginReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodGet,
		www.PoliteiaWWWAPIRoute, www.RouteUserMe, nil)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var lr www.LoginReply
	err = json.Unmarshal(respBody, &lr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal LoginReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(lr)
		if err != nil {
			return nil, err
		}
	}

	return &lr, nil
}

// Secret pings politeiawww.
func (c *Client) Secret() (*www.UserError, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		www.PoliteiaWWWAPIRoute, www.RouteSecret, nil)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var ue www.UserError
	err = json.Unmarshal(respBody, &ue)
	if err != nil {
		return nil, fmt.Errorf("unmarshal UserError: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(ue)
		if err != nil {
			return nil, err
		}
	}

	return &ue, nil
}

// ChangeUsername changes the username of the logged in user.
func (c *Client) ChangeUsername(cu *www.ChangeUsername) (*www.ChangeUsernameReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		www.PoliteiaWWWAPIRoute, www.RouteChangeUsername, cu)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var cur www.ChangeUsernameReply
	err = json.Unmarshal(respBody, &cur)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ChangeUsernameReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(cur)
		if err != nil {
			return nil, err
		}
	}

	return &cur, nil
}

// ChangePassword changes the password for the logged in user.
func (c *Client) ChangePassword(cp *www.ChangePassword) (*www.ChangePasswordReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		www.PoliteiaWWWAPIRoute, www.RouteChangePassword, cp)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var cpr www.ChangePasswordReply
	err = json.Unmarshal(respBody, &cpr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ChangePasswordReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(cpr)
		if err != nil {
			return nil, err
		}
	}

	return &cpr, nil
}

// ResetPassword resets the password of the specified user.
func (c *Client) ResetPassword(rp *www.ResetPassword) (*www.ResetPasswordReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		www.PoliteiaWWWAPIRoute, www.RouteResetPassword, rp)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var rpr www.ResetPasswordReply
	err = json.Unmarshal(respBody, &rpr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ResetPasswordReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(rpr)
		if err != nil {
			return nil, err
		}
	}

	return &rpr, nil
}

// VerifyResetPassword sends the VerifyResetPassword command to politeiawww.
func (c *Client) VerifyResetPassword(vrp www.VerifyResetPassword) (*www.VerifyResetPasswordReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		www.PoliteiaWWWAPIRoute, www.RouteVerifyResetPassword, vrp)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var reply www.VerifyResetPasswordReply
	err = json.Unmarshal(respBody, &reply)
	if err != nil {
		return nil, fmt.Errorf("unmarshal VerifyResetPasswordReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(reply)
		if err != nil {
			return nil, err
		}
	}

	return &reply, nil
}

// UserProposalPaywall retrieves proposal credit paywall information for the
// logged in user.
func (c *Client) UserProposalPaywall() (*www.UserProposalPaywallReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodGet,
		www.PoliteiaWWWAPIRoute, www.RouteUserProposalPaywall, nil)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var ppdr www.UserProposalPaywallReply
	err = json.Unmarshal(respBody, &ppdr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ProposalPaywalDetailsReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(ppdr)
		if err != nil {
			return nil, err
		}
	}

	return &ppdr, nil
}

// ProposalNew submits a new proposal.
func (c *Client) ProposalNew(pn pi.ProposalNew) (*pi.ProposalNewReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		pi.APIRoute, pi.RouteProposalNew, pn)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = piError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var pnr pi.ProposalNewReply
	err = json.Unmarshal(respBody, &pnr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ProposalNewReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(pnr)
		if err != nil {
			return nil, err
		}
	}

	return &pnr, nil
}

// ProposalEdit edits a proposal.
func (c *Client) ProposalEdit(pe pi.ProposalEdit) (*pi.ProposalEditReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		pi.APIRoute, pi.RouteProposalEdit, pe)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = piError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var per pi.ProposalEditReply
	err = json.Unmarshal(respBody, &per)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ProposalEditReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(per)
		if err != nil {
			return nil, err
		}
	}

	return &per, nil
}

// ProposalStatusSet sets the status of a proposal
func (c *Client) ProposalStatusSet(pss pi.ProposalStatusSet) (*pi.ProposalStatusSetReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		pi.APIRoute, pi.RouteProposalStatusSet, pss)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = piError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var pssr pi.ProposalStatusSetReply
	err = json.Unmarshal(respBody, &pssr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ProposalStatusSetReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(pssr)
		if err != nil {
			return nil, err
		}
	}

	return &pssr, nil
}

// Proposals retrieves a proposal for each of the provided proposal requests.
func (c *Client) Proposals(p pi.Proposals) (*pi.ProposalsReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		pi.APIRoute, pi.RouteProposals, p)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = piError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var pr pi.ProposalsReply
	err = json.Unmarshal(respBody, &pr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ProposalsReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(pr)
		if err != nil {
			return nil, err
		}
	}

	return &pr, nil
}

// ProposalInventory retrieves the censorship tokens of all proposals,
// separated by their status.
func (c *Client) ProposalInventory() (*pi.ProposalInventoryReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost, pi.APIRoute,
		pi.RouteProposalInventory, nil)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = piError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var pir pi.ProposalInventoryReply
	err = json.Unmarshal(respBody, &pir)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ProposalInventory: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(pir)
		if err != nil {
			return nil, err
		}
	}

	return &pir, nil
}

// NewInvoice submits the specified invoice to politeiawww for the logged in
// user.
func (c *Client) NewInvoice(ni *cms.NewInvoice) (*cms.NewInvoiceReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		cms.APIRoute, cms.RouteNewInvoice, ni)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var nir cms.NewInvoiceReply
	err = json.Unmarshal(respBody, &nir)
	if err != nil {
		return nil, fmt.Errorf("unmarshal NewInvoiceReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(nir)
		if err != nil {
			return nil, err
		}
	}

	return &nir, nil
}

// EditInvoice edits the specified invoice with the logged in user.
func (c *Client) EditInvoice(ei *cms.EditInvoice) (*cms.EditInvoiceReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		cms.APIRoute, cms.RouteEditInvoice, ei)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var eir cms.EditInvoiceReply
	err = json.Unmarshal(respBody, &eir)
	if err != nil {
		return nil, fmt.Errorf("unmarshal EditInvoiceReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(eir)
		if err != nil {
			return nil, err
		}
	}

	return &eir, nil
}

// ProposalDetails retrieves the specified proposal.
func (c *Client) ProposalDetails(token string, pd *www.ProposalsDetails) (*www.ProposalDetailsReply, error) {
	route := "/proposals/" + token
	statusCode, respBody, err := c.makeRequest(http.MethodGet,
		www.PoliteiaWWWAPIRoute, route, pd)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var pr www.ProposalDetailsReply
	err = json.Unmarshal(respBody, &pr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ProposalDetailsReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(pr)
		if err != nil {
			return nil, err
		}
	}

	return &pr, nil
}

// UserInvoices retrieves the proposals that have been submitted by the
// specified user.
func (c *Client) UserInvoices(up *cms.UserInvoices) (*cms.UserInvoicesReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodGet,
		cms.APIRoute, cms.RouteUserInvoices, up)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var upr cms.UserInvoicesReply
	err = json.Unmarshal(respBody, &upr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal UserInvoicesReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(upr)
		if err != nil {
			return nil, err
		}
	}

	return &upr, nil
}

// ProposalBilling retrieves the billing for the requested proposal
func (c *Client) ProposalBilling(pb *cms.ProposalBilling) (*cms.ProposalBillingReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		cms.APIRoute, cms.RouteProposalBilling, pb)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var pbr cms.ProposalBillingReply
	err = json.Unmarshal(respBody, &pbr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ProposalBillingReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(pbr)
		if err != nil {
			return nil, err
		}
	}

	return &pbr, nil
}

// ProposalBillingDetails retrieves the billing for the requested proposal
func (c *Client) ProposalBillingDetails(pbd *cms.ProposalBillingDetails) (*cms.ProposalBillingDetailsReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		cms.APIRoute, cms.RouteProposalBillingDetails, pbd)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var pbdr cms.ProposalBillingDetailsReply
	err = json.Unmarshal(respBody, &pbdr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ProposalBillingDetailsReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(pbdr)
		if err != nil {
			return nil, err
		}
	}

	return &pbdr, nil
}

// ProposalBillingSummary retrieves the billing for all approved proposals.
func (c *Client) ProposalBillingSummary(pbd *cms.ProposalBillingSummary) (*cms.ProposalBillingSummaryReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodGet,
		cms.APIRoute, cms.RouteProposalBillingSummary, pbd)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var pbdr cms.ProposalBillingSummaryReply
	err = json.Unmarshal(respBody, &pbdr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ProposalBillingSummaryReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(pbdr)
		if err != nil {
			return nil, err
		}
	}

	return &pbdr, nil
}

// Invoices retrieves invoices base on possible field set in the request
// month/year and/or status
func (c *Client) Invoices(ai *cms.Invoices) (*cms.InvoicesReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		cms.APIRoute, cms.RouteInvoices, ai)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var air cms.InvoicesReply
	err = json.Unmarshal(respBody, &air)
	if err != nil {
		return nil, fmt.Errorf("unmarshal InvoicesReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(air)
		if err != nil {
			return nil, err
		}
	}

	return &air, nil
}

// GeneratePayouts generates a list of payouts for all approved invoices that
// contain an address and amount for an admin to the process
func (c *Client) GeneratePayouts(gp *cms.GeneratePayouts) (*cms.GeneratePayoutsReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		cms.APIRoute, cms.RouteGeneratePayouts, gp)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var gpr cms.GeneratePayoutsReply
	err = json.Unmarshal(respBody, &gpr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal GeneratePayoutsReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(gpr)
		if err != nil {
			return nil, err
		}
	}

	return &gpr, nil
}

// PayInvoices is a temporary command that allows an administrator to set all
// approved invoices to the paid status. This will be removed once the
// address watching for payment is complete and working.
func (c *Client) PayInvoices(pi *cms.PayInvoices) (*cms.PayInvoicesReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodGet,
		cms.APIRoute, cms.RoutePayInvoices, pi)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var pir cms.PayInvoicesReply
	err = json.Unmarshal(respBody, &pir)
	if err != nil {
		return nil, fmt.Errorf("unmarshal PayInvoiceReply: %v", err)
	}

	return &pir, nil
}

// VoteInventory retrieves the tokens of all proposals in the inventory
// categorized by their vote status.
func (c *Client) VoteInventory() (*pi.VoteInventoryReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost, pi.APIRoute,
		pi.RouteVoteInventory, nil)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = piError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var vir pi.VoteInventoryReply
	err = json.Unmarshal(respBody, &vir)
	if err != nil {
		return nil, fmt.Errorf("unmarshal VoteInventory: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(vir)
		if err != nil {
			return nil, err
		}
	}

	return &vir, nil
}

// BatchProposals retrieves a list of proposals
func (c *Client) BatchProposals(bp *www.BatchProposals) (*www.BatchProposalsReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		www.PoliteiaWWWAPIRoute, www.RouteBatchProposals, bp)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var bpr www.BatchProposalsReply
	err = json.Unmarshal(respBody, &bpr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal BatchProposals: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(bpr)
		if err != nil {
			return nil, err
		}
	}

	return &bpr, nil
}

// VoteSummaries retrieves a summary of the voting process for a set of
// proposals.
func (c *Client) VoteSummaries(vs *pi.VoteSummaries) (*pi.VoteSummariesReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost, pi.APIRoute,
		pi.RouteVoteSummaries, vs)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = piError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var vsr pi.VoteSummariesReply
	err = json.Unmarshal(respBody, &vsr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal BatchVoteSummary: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(vsr)
		if err != nil {
			return nil, err
		}
	}

	return &vsr, nil
}

// GetAllVetted retrieves a page of vetted proposals.
func (c *Client) GetAllVetted(gav *www.GetAllVetted) (*www.GetAllVettedReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodGet,
		www.PoliteiaWWWAPIRoute, www.RouteAllVetted, gav)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var gavr www.GetAllVettedReply
	err = json.Unmarshal(respBody, &gavr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal GetAllVettedReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(gavr)
		if err != nil {
			return nil, err
		}
	}

	return &gavr, nil
}

// WWWNewComment submits a new proposal comment for the logged in user.
func (c *Client) WWWNewComment(nc *www.NewComment) (*www.NewCommentReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		www.PoliteiaWWWAPIRoute, www.RouteNewComment, nc)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var ncr www.NewCommentReply
	err = json.Unmarshal(respBody, &ncr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal NewCommentReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(ncr)
		if err != nil {
			return nil, err
		}
	}

	return &ncr, nil
}

// CommentNew submits a new proposal comment for the logged in user.
func (c *Client) CommentNew(cn pi.CommentNew) (*pi.CommentNewReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		pi.APIRoute, pi.RouteCommentNew, cn)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = piError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var cnr pi.CommentNewReply
	err = json.Unmarshal(respBody, &cnr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal CommentNewReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(cnr)
		if err != nil {
			return nil, err
		}
	}

	return &cnr, nil
}

// CommentVote casts a like comment action (upvote/downvote) for the logged in
// user.
func (c *Client) CommentVote(cv pi.CommentVote) (*pi.CommentVoteReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		pi.APIRoute, pi.RouteCommentVote, cv)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = piError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var cvr pi.CommentVoteReply
	err = json.Unmarshal(respBody, &cvr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal CommentVoteReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(cvr)
		if err != nil {
			return nil, err
		}
	}

	return &cvr, nil
}

// CommentCensor censors the specified proposal comment.
func (c *Client) CommentCensor(cc pi.CommentCensor) (*pi.CommentCensorReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost, pi.APIRoute,
		pi.RouteCommentCensor, cc)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = piError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var ccr pi.CommentCensorReply
	err = json.Unmarshal(respBody, &ccr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal CensorCommentReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(ccr)
		if err != nil {
			return nil, err
		}
	}

	return &ccr, nil
}

// Comments retrieves the comments for the specified proposal.
func (c *Client) Comments(cs pi.Comments) (*pi.CommentsReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		pi.APIRoute, pi.RouteComments, &cs)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = piError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var cr pi.CommentsReply
	err = json.Unmarshal(respBody, &cr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal CommentsReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(cr)
		if err != nil {
			return nil, err
		}
	}

	return &cr, nil
}

// CommentVotes retrieves the comment likes (upvotes/downvotes) for the
// specified proposal that are from the privoded user.
func (c *Client) CommentVotes(cv pi.CommentVotes) (*pi.CommentVotesReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		pi.APIRoute, pi.RouteCommentVotes, cv)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = piError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var cvr pi.CommentVotesReply
	err = json.Unmarshal(respBody, &cvr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal CommentVotes: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(cvr)
		if err != nil {
			return nil, err
		}
	}

	return &cvr, nil
}

// InvoiceComments retrieves the comments for the specified proposal.
func (c *Client) InvoiceComments(token string) (*www.GetCommentsReply, error) {
	route := "/invoices/" + token + "/comments"
	statusCode, respBody, err := c.makeRequest(http.MethodGet,
		cms.APIRoute, route, nil)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var gcr www.GetCommentsReply
	err = json.Unmarshal(respBody, &gcr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal InvoiceCommentsReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(gcr)
		if err != nil {
			return nil, err
		}
	}

	return &gcr, nil
}

// Votes rerieves the vote details for a given proposal.
func (c *Client) Votes(vs pi.Votes) (*pi.VotesReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		pi.APIRoute, pi.RouteVotes, vs)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = piError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var vsr pi.VotesReply
	err = json.Unmarshal(respBody, &vsr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal Votes: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(vsr)
		if err != nil {
			return nil, err
		}
	}

	return &vsr, nil
}

// WWWCensorComment censors the specified proposal comment.
func (c *Client) WWWCensorComment(cc *www.CensorComment) (*www.CensorCommentReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		www.PoliteiaWWWAPIRoute, www.RouteCensorComment, cc)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var ccr www.CensorCommentReply
	err = json.Unmarshal(respBody, &ccr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal CensorCommentReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(ccr)
		if err != nil {
			return nil, err
		}
	}

	return &ccr, nil
}

// VoteStart sends the provided VoteStart to pi.
func (c *Client) VoteStart(vs pi.VoteStart) (*pi.VoteStartReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		pi.APIRoute, pi.RouteVoteStart, vs)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = piError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var vsr pi.VoteStartReply
	err = json.Unmarshal(respBody, &vsr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal VoteStartReply: %v", err)
	}

	if c.cfg.Verbose {
		vsr.EligibleTickets = []string{"removed by piwww for readability"}
		err := prettyPrintJSON(vsr)
		if err != nil {
			return nil, err
		}
	}

	return &vsr, nil
}

// VoteStartRunoff sends the given VoteStartRunoff to the pi api
// RouteVoteStartRunoff and returns the reply.
func (c *Client) VoteStartRunoff(vsr pi.VoteStartRunoff) (*pi.VoteStartRunoffReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		pi.APIRoute, pi.RouteVoteStartRunoff, vsr)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = piError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var vsrr pi.VoteStartRunoffReply
	err = json.Unmarshal(respBody, &vsrr)
	if err != nil {
		return nil, err
	}

	if c.cfg.Verbose {
		vsrr.EligibleTickets = []string{"removed by piwww for readability"}
		err := prettyPrintJSON(vsrr)
		if err != nil {
			return nil, err
		}
	}

	return &vsrr, nil
}

// UserRegistrationPayment checks whether the logged in user has paid their user
// registration fee.
func (c *Client) UserRegistrationPayment() (*www.UserRegistrationPaymentReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodGet,
		www.PoliteiaWWWAPIRoute, www.RouteUserRegistrationPayment, nil)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var urpr www.UserRegistrationPaymentReply
	err = json.Unmarshal(respBody, &urpr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal UserRegistrationPaymentReply: %v",
			err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(urpr)
		if err != nil {
			return nil, err
		}
	}

	return &urpr, nil
}

// VoteResults retrieves the vote results for the specified proposal.
func (c *Client) VoteResults(vr pi.VoteResults) (*pi.VoteResultsReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodGet,
		pi.APIRoute, pi.RouteVoteResults, vr)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = piError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var vrr pi.VoteResultsReply
	err = json.Unmarshal(respBody, &vrr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ProposalVotesReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(vrr)
		if err != nil {
			return nil, err
		}
	}

	return &vrr, nil
}

// VoteDetailsV2 returns the proposal vote details for the given token using
// the www v2 VoteDetails route.
func (c *Client) VoteDetailsV2(token string) (*www2.VoteDetailsReply, error) {
	route := "/vote/" + token
	statusCode, respBody, err := c.makeRequest(http.MethodGet, www2.APIRoute,
		route, nil)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var vdr www2.VoteDetailsReply
	err = json.Unmarshal(respBody, &vdr)
	if err != nil {
		return nil, err
	}

	if c.cfg.Verbose {
		vdr.EligibleTickets = []string{
			"removed by piwww for readability",
		}
		err = prettyPrintJSON(vdr)
		if err != nil {
			return nil, err
		}
	}

	return &vdr, nil
}

// UserDetails retrieves the user details for the specified user.
func (c *Client) UserDetails(userID string) (*www.UserDetailsReply, error) {
	route := "/user/" + userID
	statusCode, respBody, err := c.makeRequest(http.MethodGet,
		www.PoliteiaWWWAPIRoute, route, nil)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var udr www.UserDetailsReply
	err = json.Unmarshal(respBody, &udr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal UserDetailsReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(udr)
		if err != nil {
			return nil, err
		}
	}

	return &udr, nil
}

// Users retrieves a list of users that adhere to the specified filtering
// parameters.
func (c *Client) Users(u *www.Users) (*www.UsersReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodGet,
		www.PoliteiaWWWAPIRoute, www.RouteUsers, u)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var ur www.UsersReply
	err = json.Unmarshal(respBody, &ur)
	if err != nil {
		return nil, fmt.Errorf("unmarshal UsersReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(ur)
		if err != nil {
			return nil, err
		}
	}

	return &ur, nil
}

// CMSUsers retrieves a list of cms users that adhere to the specified filtering
// parameters.
func (c *Client) CMSUsers(cu *cms.CMSUsers) (*cms.CMSUsersReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodGet, cms.APIRoute,
		cms.RouteCMSUsers, cu)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var cur cms.CMSUsersReply
	err = json.Unmarshal(respBody, &cur)
	if err != nil {
		return nil, fmt.Errorf("unmarshal CMSUsersReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(cur)
		if err != nil {
			return nil, err
		}
	}

	return &cur, nil
}

// ManageUser allows an admin to edit certain attributes of the specified user.
func (c *Client) ManageUser(mu *www.ManageUser) (*www.ManageUserReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		www.PoliteiaWWWAPIRoute, www.RouteManageUser, mu)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var mur www.ManageUserReply
	err = json.Unmarshal(respBody, &mur)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ManageUserReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(mur)
		if err != nil {
			return nil, err
		}
	}

	return &mur, nil
}

// EditUser allows the logged in user to update their user settings.
func (c *Client) EditUser(eu *www.EditUser) (*www.EditUserReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		www.PoliteiaWWWAPIRoute, www.RouteEditUser, eu)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var eur www.EditUserReply
	err = json.Unmarshal(respBody, &eur)
	if err != nil {
		return nil, fmt.Errorf("unmarshal EditUserReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(eur)
		if err != nil {
			return nil, err
		}
	}

	return &eur, nil
}

// VoteAuthorize authorizes the voting period for the specified proposal using
// the logged in user.
func (c *Client) VoteAuthorize(va pi.VoteAuthorize) (*pi.VoteAuthorizeReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost, pi.APIRoute,
		pi.RouteVoteAuthorize, va)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = piError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var vr pi.VoteAuthorizeReply
	err = json.Unmarshal(respBody, &vr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal VoteAuthorizeReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(vr)
		if err != nil {
			return nil, err
		}
	}

	return &vr, nil
}

// VoteStatus retrieves the vote status for the specified proposal.
func (c *Client) VoteStatus(token string) (*www.VoteStatusReply, error) {
	route := "/proposals/" + token + "/votestatus"
	statusCode, respBody, err := c.makeRequest(http.MethodGet,
		www.PoliteiaWWWAPIRoute, route, nil)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var vsr www.VoteStatusReply
	err = json.Unmarshal(respBody, &vsr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal VoteStatusReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(vsr)
		if err != nil {
			return nil, err
		}
	}

	return &vsr, nil
}

// GetAllVoteStatus retreives the vote status of all public proposals.
func (c *Client) GetAllVoteStatus() (*www.GetAllVoteStatusReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodGet,
		www.PoliteiaWWWAPIRoute, www.RouteAllVoteStatus, nil)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var avsr www.GetAllVoteStatusReply
	err = json.Unmarshal(respBody, &avsr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal GetAllVoteStatusReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(avsr)
		if err != nil {
			return nil, fmt.Errorf("prettyPrintJSON: %v", err)
		}
	}

	return &avsr, nil
}

// ActiveVotesDCC retreives all dccs that are currently being voted on.
func (c *Client) ActiveVotesDCC() (*cms.ActiveVoteReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodGet,
		www.PoliteiaWWWAPIRoute, cms.RouteActiveVotesDCC, nil)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var avr cms.ActiveVoteReply
	err = json.Unmarshal(respBody, &avr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ActiveVoteDCCReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(avr)
		if err != nil {
			return nil, err
		}
	}

	return &avr, nil
}

// VoteBallot casts ballot of votes for a proposal.
func (c *Client) VoteBallot(vb *pi.VoteBallot) (*pi.VoteBallotReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		pi.APIRoute, pi.RouteVoteBallot, &vb)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = piError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var vbr pi.VoteBallotReply
	err = json.Unmarshal(respBody, &vbr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal VoteBallotReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(vbr)
		if err != nil {
			return nil, err
		}
	}

	return &vbr, nil
}

// UpdateUserKey updates the identity of the logged in user.
func (c *Client) UpdateUserKey(uuk *www.UpdateUserKey) (*www.UpdateUserKeyReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		www.PoliteiaWWWAPIRoute, www.RouteUpdateUserKey, &uuk)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var uukr www.UpdateUserKeyReply
	err = json.Unmarshal(respBody, &uukr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal UpdateUserKeyReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(uukr)
		if err != nil {
			return nil, err
		}
	}

	return &uukr, nil
}

// VerifyUpdateUserKey is used to verify a new user identity.
func (c *Client) VerifyUpdateUserKey(vuuk *www.VerifyUpdateUserKey) (*www.VerifyUpdateUserKeyReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		www.PoliteiaWWWAPIRoute, www.RouteVerifyUpdateUserKey, &vuuk)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var vuukr www.VerifyUpdateUserKeyReply
	err = json.Unmarshal(respBody, &vuukr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal VerifyUpdateUserKeyReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(vuukr)
		if err != nil {
			return nil, err
		}
	}

	return &vuukr, nil
}

// UserProposalPaywallTx retrieves payment details of any pending proposal
// credit payment from the logged in user.
func (c *Client) UserProposalPaywallTx() (*www.UserProposalPaywallTxReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodGet,
		www.PoliteiaWWWAPIRoute, www.RouteUserProposalPaywallTx, nil)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var upptxr www.UserProposalPaywallTxReply
	err = json.Unmarshal(respBody, &upptxr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ProposalPaywallPaymentReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(upptxr)
		if err != nil {
			return nil, err
		}
	}

	return &upptxr, nil
}

// UserPaymentsRescan scans the specified user's paywall address and makes sure
// that the user's account has been properly credited with all payments.
func (c *Client) UserPaymentsRescan(upr *www.UserPaymentsRescan) (*www.UserPaymentsRescanReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPut,
		www.PoliteiaWWWAPIRoute, www.RouteUserPaymentsRescan, upr)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var uprr www.UserPaymentsRescanReply
	err = json.Unmarshal(respBody, &uprr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal UserPaymentsRescanReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(uprr)
		if err != nil {
			return nil, err
		}
	}

	return &uprr, nil
}

// UserProposalCredits retrieves the proposal credit history for the logged
// in user.
func (c *Client) UserProposalCredits() (*www.UserProposalCreditsReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodGet,
		www.PoliteiaWWWAPIRoute, www.RouteUserProposalCredits, nil)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var upcr www.UserProposalCreditsReply
	err = json.Unmarshal(respBody, &upcr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal UserProposalCreditsReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(upcr)
		if err != nil {
			return nil, err
		}
	}

	return &upcr, nil
}

// ResendVerification re-sends the user verification email for an unverified
// user.
func (c *Client) ResendVerification(rv www.ResendVerification) (*www.ResendVerificationReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		www.PoliteiaWWWAPIRoute, www.RouteResendVerification, rv)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var rvr www.ResendVerificationReply
	err = json.Unmarshal(respBody, &rvr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ResendVerificationReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(rvr)
		if err != nil {
			return nil, err
		}
	}

	return &rvr, nil
}

// InvoiceDetails retrieves the specified invoice.
func (c *Client) InvoiceDetails(token string, id *cms.InvoiceDetails) (*cms.InvoiceDetailsReply, error) {
	route := "/invoices/" + token
	statusCode, respBody, err := c.makeRequest(http.MethodGet, cms.APIRoute,
		route, id)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var idr cms.InvoiceDetailsReply
	err = json.Unmarshal(respBody, &idr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal InvoiceDetailsReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(idr)
		if err != nil {
			return nil, err
		}
	}

	return &idr, nil
}

// SetInvoiceStatus changes the status of the specified invoice.
func (c *Client) SetInvoiceStatus(sis *cms.SetInvoiceStatus) (*cms.SetInvoiceStatusReply, error) {
	route := "/invoices/" + sis.Token + "/status"
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		cms.APIRoute, route, sis)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var sisr cms.SetInvoiceStatusReply
	err = json.Unmarshal(respBody, &sisr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal SetInvoiceStatusReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(sisr)
		if err != nil {
			return nil, err
		}
	}

	return &sisr, nil
}

// TokenInventory retrieves the censorship record tokens of all proposals in
// the inventory.
func (c *Client) TokenInventory() (*www.TokenInventoryReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodGet,
		www.PoliteiaWWWAPIRoute, www.RouteTokenInventory, nil)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var tir www.TokenInventoryReply
	err = json.Unmarshal(respBody, &tir)
	if err != nil {
		return nil, fmt.Errorf("unmarshal TokenInventoryReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(tir)
		if err != nil {
			return nil, err
		}
	}

	return &tir, nil
}

// InvoiceExchangeRate changes the status of the specified invoice.
func (c *Client) InvoiceExchangeRate(ier *cms.InvoiceExchangeRate) (*cms.InvoiceExchangeRateReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		cms.APIRoute, cms.RouteInvoiceExchangeRate, ier)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var ierr cms.InvoiceExchangeRateReply
	err = json.Unmarshal(respBody, &ierr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal SetInvoiceStatusReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(ierr)
		if err != nil {
			return nil, err
		}
	}
	return &ierr, nil
}

// InvoicePayouts retrieves invoices base on possible field set in the request
// month/year and/or status
func (c *Client) InvoicePayouts(lip *cms.InvoicePayouts) (*cms.InvoicePayoutsReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		cms.APIRoute, cms.RouteInvoicePayouts, lip)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var lipr cms.InvoicePayoutsReply
	err = json.Unmarshal(respBody, &lipr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal InvoicePayouts: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(lipr)
		if err != nil {
			return nil, err
		}
	}
	return &lipr, nil
}

// CMSUserDetails returns the current cms user's information.
func (c *Client) CMSUserDetails(userID string) (*cms.UserDetailsReply, error) {
	route := "/user/" + userID
	statusCode, respBody, err := c.makeRequest(http.MethodGet, cms.APIRoute,
		route, nil)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var uir cms.UserDetailsReply
	err = json.Unmarshal(respBody, &uir)
	if err != nil {
		return nil, fmt.Errorf("unmarshal CMSUserDetailsReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(uir)
		if err != nil {
			return nil, err
		}
	}

	return &uir, nil
}

// CMSEditUser edits the current user's information.
func (c *Client) CMSEditUser(uui cms.EditUser) (*cms.EditUserReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		cms.APIRoute, www.RouteEditUser, uui)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var eur cms.EditUserReply
	err = json.Unmarshal(respBody, &eur)
	if err != nil {
		return nil, fmt.Errorf("unmarshal CMSEditUserReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(eur)
		if err != nil {
			return nil, err
		}
	}

	return &eur, nil
}

// CMSManageUser updates the given user's information.
func (c *Client) CMSManageUser(uui cms.CMSManageUser) (*cms.CMSManageUserReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost, cms.APIRoute,
		cms.RouteManageCMSUser, uui)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var eur cms.CMSManageUserReply
	err = json.Unmarshal(respBody, &eur)
	if err != nil {
		return nil, fmt.Errorf("unmarshal CMSManageUserReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(eur)
		if err != nil {
			return nil, err
		}
	}

	return &eur, nil
}

// NewDCC creates a new dcc proposal.
func (c *Client) NewDCC(nd cms.NewDCC) (*cms.NewDCCReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		cms.APIRoute, cms.RouteNewDCC, nd)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var ndr cms.NewDCCReply
	err = json.Unmarshal(respBody, &ndr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal NewDCCReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(ndr)
		if err != nil {
			return nil, err
		}
	}

	return &ndr, nil
}

// SupportOpposeDCC issues support for a given DCC proposal.
func (c *Client) SupportOpposeDCC(sd cms.SupportOpposeDCC) (*cms.SupportOpposeDCCReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		cms.APIRoute, cms.RouteSupportOpposeDCC, sd)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var sdr cms.SupportOpposeDCCReply
	err = json.Unmarshal(respBody, &sdr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal SupportOpposeDCCReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(sdr)
		if err != nil {
			return nil, err
		}
	}

	return &sdr, nil
}

// NewDCCComment submits a new dcc comment for the logged in user.
func (c *Client) NewDCCComment(nc *www.NewComment) (*www.NewCommentReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		cms.APIRoute, cms.RouteNewCommentDCC, nc)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var ncr www.NewCommentReply
	err = json.Unmarshal(respBody, &ncr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal NewDCCCommentReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(ncr)
		if err != nil {
			return nil, err
		}
	}

	return &ncr, nil
}

// DCCComments retrieves the comments for the specified proposal.
func (c *Client) DCCComments(token string) (*www.GetCommentsReply, error) {
	route := "/dcc/" + token + "/comments"
	statusCode, respBody, err := c.makeRequest(http.MethodGet, cms.APIRoute,
		route, nil)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var gcr www.GetCommentsReply
	err = json.Unmarshal(respBody, &gcr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal DCCCommentsReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(gcr)
		if err != nil {
			return nil, err
		}
	}

	return &gcr, nil
}

// DCCDetails retrieves the specified dcc.
func (c *Client) DCCDetails(token string) (*cms.DCCDetailsReply, error) {
	route := "/dcc/" + token
	statusCode, respBody, err := c.makeRequest(http.MethodGet, cms.APIRoute,
		route, nil)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var ddr cms.DCCDetailsReply
	err = json.Unmarshal(respBody, &ddr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal DCCDetailsReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(ddr)
		if err != nil {
			return nil, err
		}
	}

	return &ddr, nil
}

// GetDCCs retrieves invoices base on possible field set in the request
// month/year and/or status
func (c *Client) GetDCCs(gd *cms.GetDCCs) (*cms.GetDCCsReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		cms.APIRoute, cms.RouteGetDCCs, gd)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var gdr cms.GetDCCsReply
	err = json.Unmarshal(respBody, &gdr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal GetDCCsReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(gdr)
		if err != nil {
			return nil, err
		}
	}

	return &gdr, nil
}

// SetDCCStatus issues an status update for a given DCC proposal.
func (c *Client) SetDCCStatus(sd *cms.SetDCCStatus) (*cms.SetDCCStatusReply, error) {
	route := "/dcc/" + sd.Token + "/status"
	statusCode, respBody, err := c.makeRequest(http.MethodPost, cms.APIRoute,
		route, sd)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var sdr cms.SetDCCStatusReply
	err = json.Unmarshal(respBody, &sdr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal SetDCCStatusReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(sdr)
		if err != nil {
			return nil, err
		}
	}

	return &sdr, nil
}

// UserSubContractors retrieves the subcontractors that are linked to the requesting user
func (c *Client) UserSubContractors(usc *cms.UserSubContractors) (*cms.UserSubContractorsReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodGet,
		cms.APIRoute, cms.RouteUserSubContractors, usc)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var uscr cms.UserSubContractorsReply
	err = json.Unmarshal(respBody, &uscr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal UserSubContractorsReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(uscr)
		if err != nil {
			return nil, err
		}
	}
	return &uscr, nil
}

// ProposalOwner retrieves the subcontractors that are linked to the requesting user
func (c *Client) ProposalOwner(po *cms.ProposalOwner) (*cms.ProposalOwnerReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodGet,
		cms.APIRoute, cms.RouteProposalOwner, po)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var por cms.ProposalOwnerReply
	err = json.Unmarshal(respBody, &por)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ProposalOwnerReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(por)
		if err != nil {
			return nil, err
		}
	}

	return &por, nil
}

// CastVoteDCC issues a signed vote for a given DCC proposal. approval
func (c *Client) CastVoteDCC(cv cms.CastVote) (*cms.CastVoteReply, error) {
	statusCode, respBody, err := c.makeRequest("POST", cms.APIRoute,
		cms.RouteCastVoteDCC, cv)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var cvr cms.CastVoteReply
	err = json.Unmarshal(respBody, &cvr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal VoteDCCReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(cvr)
		if err != nil {
			return nil, err
		}
	}

	return &cvr, nil
}

// VoteDetailsDCC returns all the needed information about a given vote for a
// DCC proposal.
func (c *Client) VoteDetailsDCC(cv cms.VoteDetails) (*cms.VoteDetailsReply, error) {
	statusCode, respBody, err := c.makeRequest("POST", cms.APIRoute,
		cms.RouteVoteDetailsDCC, cv)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var vdr cms.VoteDetailsReply
	err = json.Unmarshal(respBody, &vdr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal VoteDCCReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(vdr)
		if err != nil {
			return nil, err
		}
	}

	return &vdr, nil
}

// StartVoteDCC sends the provided StartVoteDCC to the politeiawww backend.
func (c *Client) StartVoteDCC(sv cms.StartVote) (*cms.StartVoteReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		cms.APIRoute, cms.RouteStartVoteDCC, sv)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var svr cms.StartVoteReply
	err = json.Unmarshal(respBody, &svr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal StartVoteReply: %v", err)
	}

	if c.cfg.Verbose {
		svr.UserWeights = []string{"removed by piwww for readability"}
		err := prettyPrintJSON(svr)
		if err != nil {
			return nil, err
		}
	}

	return &svr, nil
}

// WalletAccounts retrieves the walletprc accounts.
func (c *Client) WalletAccounts() (*walletrpc.AccountsResponse, error) {
	if c.wallet == nil {
		return nil, fmt.Errorf("walletrpc client not loaded")
	}

	if c.cfg.Verbose {
		fmt.Printf("walletrpc %v Accounts\n", c.cfg.WalletHost)
	}

	ar, err := c.wallet.Accounts(c.ctx, &walletrpc.AccountsRequest{})
	if err != nil {
		return nil, err
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(ar)
		if err != nil {
			return nil, err
		}
	}

	return ar, nil
}

// CommittedTickets returns the committed tickets that belong to the dcrwallet
// instance out of the the specified list of tickets.
func (c *Client) CommittedTickets(ct *walletrpc.CommittedTicketsRequest) (*walletrpc.CommittedTicketsResponse, error) {
	if c.wallet == nil {
		return nil, fmt.Errorf("walletrpc client not loaded")
	}

	if c.cfg.Verbose {
		fmt.Printf("walletrpc %v CommittedTickets\n", c.cfg.WalletHost)
	}

	ctr, err := c.wallet.CommittedTickets(c.ctx, ct)
	if err != nil {
		return nil, err
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(ctr)
		if err != nil {
			return nil, err
		}
	}

	return ctr, nil
}

// SignMessages signs the passed in messages using the private keys from the
// specified addresses.
func (c *Client) SignMessages(sm *walletrpc.SignMessagesRequest) (*walletrpc.SignMessagesResponse, error) {
	if c.wallet == nil {
		return nil, fmt.Errorf("walletrpc client not loaded")
	}

	if c.cfg.Verbose {
		fmt.Printf("walletrpc %v SignMessages\n", c.cfg.WalletHost)
	}

	smr, err := c.wallet.SignMessages(c.ctx, sm)
	if err != nil {
		return nil, err
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(smr)
		if err != nil {
			return nil, err
		}
	}

	return smr, nil
}

// SetTOTP sets the logged in user's TOTP Key.
func (c *Client) SetTOTP(st *www.SetTOTP) (*www.SetTOTPReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		cms.APIRoute, www.RouteSetTOTP, st)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var str www.SetTOTPReply
	err = json.Unmarshal(respBody, &str)
	if err != nil {
		return nil, fmt.Errorf("unmarshal SetTOTPReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(str)
		if err != nil {
			return nil, err
		}
	}

	return &str, nil
}

// VerifyTOTP comfirms the logged in user's TOTP Key.
func (c *Client) VerifyTOTP(vt *www.VerifyTOTP) (*www.VerifyTOTPReply, error) {
	statusCode, respBody, err := c.makeRequest(http.MethodPost,
		cms.APIRoute, www.RouteVerifyTOTP, vt)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		err = wwwError(respBody, statusCode)
		if err != nil {
			return nil, err
		}
	}

	var vtr www.VerifyTOTPReply
	err = json.Unmarshal(respBody, &vtr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal VerifyTOTPReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(vtr)
		if err != nil {
			return nil, err
		}
	}

	return &vtr, nil
}

// LoadWalletClient connects to a dcrwallet instance.
func (c *Client) LoadWalletClient() error {
	creds, err := credentials.NewClientTLSFromFile(c.cfg.WalletCert, "")
	if err != nil {
		return err
	}

	conn, err := grpc.Dial(c.cfg.WalletHost,
		grpc.WithTransportCredentials(creds))
	if err != nil {
		return err
	}

	c.ctx = context.Background()
	c.creds = creds
	c.conn = conn
	c.wallet = walletrpc.NewWalletServiceClient(conn)
	return nil
}

// Close all client connections.
func (c *Client) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

// NewClient returns a new politeiawww client.
func NewClient(cfg *Config) (*Client, error) {
	// Create http client
	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.SkipVerify,
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
