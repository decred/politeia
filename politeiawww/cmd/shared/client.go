// Copyright (c) 2017-2019 The Decred developers
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

	"github.com/decred/dcrwallet/rpc/walletrpc"
	cms "github.com/thi4go/politeia/politeiawww/api/cms/v1"
	www "github.com/thi4go/politeia/politeiawww/api/www/v1"
	www2 "github.com/thi4go/politeia/politeiawww/api/www/v2"
	"github.com/thi4go/politeia/util"
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

// userErrorStatus retrieves the human readable error message for an error
// status code. The status code can be from either the pi or cms api.
func userErrorStatus(e www.ErrorStatusT) string {
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

// makeRequest sends the provided request to the politeiawww backend specified
// by the Client config. This function handles verbose printing when specified
// by the Client config since verbose printing includes details such as the
// full route and http response codes.
func (c *Client) makeRequest(method, routeVersion, route string, body interface{}) ([]byte, error) {
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
				return nil, err
			}
			queryParams = "?" + form.Encode()

		case method == http.MethodPost || method == http.MethodPut:
			var err error
			requestBody, err = json.Marshal(body)
			if err != nil {
				return nil, err
			}

		default:
			return nil, fmt.Errorf("unknown http method '%v'", method)
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
			return nil, err
		}
	case c.cfg.Verbose && method == http.MethodPut:
		fmt.Printf("Request: PUT %v\n", fullRoute)
		err := prettyPrintJSON(body)
		if err != nil {
			return nil, err
		}
	}

	// Create http request
	req, err := http.NewRequest(method, fullRoute, bytes.NewReader(requestBody))
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

	responseBody := util.ConvertBodyToByteArray(r.Body, false)

	// Validate response status
	if r.StatusCode != http.StatusOK {
		var ue www.UserError
		err = json.Unmarshal(responseBody, &ue)
		if err == nil && ue.ErrorCode != 0 {
			var e error
			if len(ue.ErrorContext) == 0 {
				// Error format when an ErrorContext is not included
				e = fmt.Errorf("%v, %v", r.StatusCode, userErrorStatus(ue.ErrorCode))
			} else {
				// Error format when an ErrorContext is included
				e = fmt.Errorf("%v, %v: %v", r.StatusCode,
					userErrorStatus(ue.ErrorCode), strings.Join(ue.ErrorContext, ", "))
			}
			return nil, e
		}

		return nil, fmt.Errorf("%v", r.StatusCode)
	}

	// Print response details
	if c.cfg.Verbose {
		fmt.Printf("Response: %v\n", r.StatusCode)
	}

	return responseBody, nil
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

	responseBody := util.ConvertBodyToByteArray(r.Body, false)

	// Validate response status
	if r.StatusCode != http.StatusOK {
		var ue www.UserError
		err = json.Unmarshal(responseBody, &ue)
		if err == nil {
			return nil, fmt.Errorf("%v, %v %v", r.StatusCode,
				userErrorStatus(ue.ErrorCode), strings.Join(ue.ErrorContext, ", "))
		}

		return nil, fmt.Errorf("%v", r.StatusCode)
	}

	// Unmarshal response
	var vr www.VersionReply
	err = json.Unmarshal(responseBody, &vr)
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

	responseBody := util.ConvertBodyToByteArray(r.Body, false)

	// Validate response status
	if r.StatusCode != http.StatusOK {
		var ue www.UserError
		err = json.Unmarshal(responseBody, &ue)
		if err == nil {
			return nil, fmt.Errorf("%v, %v %v", r.StatusCode,
				userErrorStatus(ue.ErrorCode), strings.Join(ue.ErrorContext, ", "))
		}

		return nil, fmt.Errorf("%v", r.StatusCode)
	}

	// Unmarshal response
	var lr www.LoginReply
	err = json.Unmarshal(responseBody, &lr)
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

	responseBody := util.ConvertBodyToByteArray(r.Body, false)

	// Validate response status
	if r.StatusCode != http.StatusOK {
		var ue www.UserError
		err = json.Unmarshal(responseBody, &ue)
		if err == nil {
			return nil, fmt.Errorf("%v, %v %v", r.StatusCode,
				userErrorStatus(ue.ErrorCode), strings.Join(ue.ErrorContext, ", "))
		}

		return nil, fmt.Errorf("%v", r.StatusCode)
	}

	// Unmarshal response
	var lr www.LogoutReply
	err = json.Unmarshal(responseBody, &lr)
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
	responseBody, err := c.makeRequest(http.MethodGet,
		www.PoliteiaWWWAPIRoute, www.RoutePolicy, nil)
	if err != nil {
		return nil, err
	}

	var pr www.PolicyReply
	err = json.Unmarshal(responseBody, &pr)
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
	responseBody, err := c.makeRequest(http.MethodGet,
		www.PoliteiaWWWAPIRoute, www.RoutePolicy, nil)
	if err != nil {
		return nil, err
	}

	var pr cms.PolicyReply
	err = json.Unmarshal(responseBody, &pr)
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
	responseBody, err := c.makeRequest(http.MethodPost,
		cms.APIRoute, cms.RouteInviteNewUser, inu)
	if err != nil {
		return nil, err
	}

	var inur cms.InviteNewUserReply
	err = json.Unmarshal(responseBody, &inur)
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
	responseBody, err := c.makeRequest(http.MethodPost,
		cms.APIRoute, cms.RouteRegisterUser, ru)
	if err != nil {
		return nil, err
	}

	var rur cms.RegisterUserReply
	err = json.Unmarshal(responseBody, &rur)
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
	responseBody, err := c.makeRequest(http.MethodPost,
		www.PoliteiaWWWAPIRoute, www.RouteNewUser, nu)
	if err != nil {
		return nil, err
	}

	var nur www.NewUserReply
	err = json.Unmarshal(responseBody, &nur)
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
	responseBody, err := c.makeRequest(http.MethodGet,
		www.PoliteiaWWWAPIRoute, www.RouteVerifyNewUser, vnu)
	if err != nil {
		return nil, err
	}

	var vnur www.VerifyNewUserReply
	err = json.Unmarshal(responseBody, &vnur)
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
	responseBody, err := c.makeRequest(http.MethodGet,
		www.PoliteiaWWWAPIRoute, www.RouteUserMe, nil)
	if err != nil {
		return nil, err
	}

	var lr www.LoginReply
	err = json.Unmarshal(responseBody, &lr)
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
	responseBody, err := c.makeRequest(http.MethodPost,
		www.PoliteiaWWWAPIRoute, www.RouteSecret, nil)
	if err != nil {
		return nil, err
	}

	var ue www.UserError
	err = json.Unmarshal(responseBody, &ue)
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
	responseBody, err := c.makeRequest(http.MethodPost,
		www.PoliteiaWWWAPIRoute, www.RouteChangeUsername, cu)
	if err != nil {
		return nil, err
	}

	var cur www.ChangeUsernameReply
	err = json.Unmarshal(responseBody, &cur)
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
	responseBody, err := c.makeRequest(http.MethodPost,
		www.PoliteiaWWWAPIRoute, www.RouteChangePassword, cp)
	if err != nil {
		return nil, err
	}

	var cpr www.ChangePasswordReply
	err = json.Unmarshal(responseBody, &cpr)
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
	responseBody, err := c.makeRequest(http.MethodPost,
		www.PoliteiaWWWAPIRoute, www.RouteResetPassword, rp)
	if err != nil {
		return nil, err
	}

	var rpr www.ResetPasswordReply
	err = json.Unmarshal(responseBody, &rpr)
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
	respBody, err := c.makeRequest(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteVerifyResetPassword, vrp)
	if err != nil {
		return nil, err
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

// ProposalPaywallDetails retrieves proposal credit paywall information for the
// logged in user.
func (c *Client) ProposalPaywallDetails() (*www.ProposalPaywallDetailsReply, error) {
	responseBody, err := c.makeRequest(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteProposalPaywallDetails, nil)
	if err != nil {
		return nil, err
	}

	var ppdr www.ProposalPaywallDetailsReply
	err = json.Unmarshal(responseBody, &ppdr)
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

// NewProposal submits the specified proposal to politeiawww for the logged in
// user.
func (c *Client) NewProposal(np *www.NewProposal) (*www.NewProposalReply, error) {
	responseBody, err := c.makeRequest(http.MethodPost,
		www.PoliteiaWWWAPIRoute, www.RouteNewProposal, np)
	if err != nil {
		return nil, err
	}

	var npr www.NewProposalReply
	err = json.Unmarshal(responseBody, &npr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal NewProposalReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(npr)
		if err != nil {
			return nil, err
		}
	}

	return &npr, nil
}

// EditProposal edits the specified proposal with the logged in user.
func (c *Client) EditProposal(ep *www.EditProposal) (*www.EditProposalReply, error) {
	responseBody, err := c.makeRequest(http.MethodPost,
		www.PoliteiaWWWAPIRoute, www.RouteEditProposal, ep)
	if err != nil {
		return nil, err
	}

	var epr www.EditProposalReply
	err = json.Unmarshal(responseBody, &epr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal EditProposalReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(epr)
		if err != nil {
			return nil, err
		}
	}

	return &epr, nil
}

// NewInvoice submits the specified invoice to politeiawww for the logged in
// user.
func (c *Client) NewInvoice(ni *cms.NewInvoice) (*cms.NewInvoiceReply, error) {
	responseBody, err := c.makeRequest(http.MethodPost,
		cms.APIRoute, cms.RouteNewInvoice, ni)
	if err != nil {
		return nil, err
	}

	var nir cms.NewInvoiceReply
	err = json.Unmarshal(responseBody, &nir)
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
	responseBody, err := c.makeRequest(http.MethodPost,
		cms.APIRoute, cms.RouteEditInvoice, ei)
	if err != nil {
		return nil, err
	}

	var eir cms.EditInvoiceReply
	err = json.Unmarshal(responseBody, &eir)
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
	responseBody, err := c.makeRequest(http.MethodGet,
		www.PoliteiaWWWAPIRoute, route, pd)
	if err != nil {
		return nil, err
	}

	var pr www.ProposalDetailsReply
	err = json.Unmarshal(responseBody, &pr)
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

// UserProposals retrieves the proposals that have been submitted by the
// specified user.
func (c *Client) UserProposals(up *www.UserProposals) (*www.UserProposalsReply, error) {
	responseBody, err := c.makeRequest(http.MethodGet,
		www.PoliteiaWWWAPIRoute, www.RouteUserProposals, up)
	if err != nil {
		return nil, err
	}

	var upr www.UserProposalsReply
	err = json.Unmarshal(responseBody, &upr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal UserProposalsReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(upr)
		if err != nil {
			return nil, err
		}
	}

	return &upr, nil
}

// UserInvoices retrieves the proposals that have been submitted by the
// specified user.
func (c *Client) UserInvoices(up *cms.UserInvoices) (*cms.UserInvoicesReply, error) {
	responseBody, err := c.makeRequest(http.MethodGet,
		cms.APIRoute, cms.RouteUserInvoices, up)
	if err != nil {
		return nil, err
	}

	var upr cms.UserInvoicesReply
	err = json.Unmarshal(responseBody, &upr)
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

// AdminInvoices retrieves invoices base on possible field set in the request
// month/year and/or status
func (c *Client) AdminInvoices(ai *cms.AdminInvoices) (*cms.AdminInvoicesReply, error) {
	responseBody, err := c.makeRequest(http.MethodPost,
		cms.APIRoute, cms.RouteAdminInvoices, ai)
	if err != nil {
		return nil, err
	}

	var air cms.AdminInvoicesReply
	err = json.Unmarshal(responseBody, &air)
	if err != nil {
		return nil, fmt.Errorf("unmarshal AdminInvoicesReply: %v", err)
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
	responseBody, err := c.makeRequest(http.MethodPost,
		cms.APIRoute, cms.RouteGeneratePayouts, gp)
	if err != nil {
		return nil, err
	}

	var gpr cms.GeneratePayoutsReply
	err = json.Unmarshal(responseBody, &gpr)
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
	responseBody, err := c.makeRequest(http.MethodGet,
		cms.APIRoute, cms.RoutePayInvoices, pi)
	if err != nil {
		return nil, err
	}

	var pir cms.PayInvoicesReply
	err = json.Unmarshal(responseBody, &pir)
	if err != nil {
		return nil, fmt.Errorf("unmarshal PayInvoiceReply: %v", err)
	}

	return &pir, nil
}

// SetProposalStatus changes the status of the specified proposal.
func (c *Client) SetProposalStatus(sps *www.SetProposalStatus) (*www.SetProposalStatusReply, error) {
	route := "/proposals/" + sps.Token + "/status"
	responseBody, err := c.makeRequest(http.MethodPost,
		www.PoliteiaWWWAPIRoute, route, sps)
	if err != nil {
		return nil, err
	}

	var spsr www.SetProposalStatusReply
	err = json.Unmarshal(responseBody, &spsr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal SetProposalStatusReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(spsr)
		if err != nil {
			return nil, err
		}
	}

	return &spsr, nil
}

// BatchProposals retrieves a list of proposals
func (c *Client) BatchProposals(bp *www.BatchProposals) (*www.BatchProposalsReply, error) {
	responseBody, err := c.makeRequest(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteBatchProposals, bp)
	if err != nil {
		return nil, err
	}

	var bpr www.BatchProposalsReply
	err = json.Unmarshal(responseBody, &bpr)
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

// BatchVoteSummary retrieves a summary of the voting process for a set of
// proposals.
func (c *Client) BatchVoteSummary(bvs *www.BatchVoteSummary) (*www.BatchVoteSummaryReply, error) {
	responseBody, err := c.makeRequest(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteBatchVoteSummary, bvs)
	if err != nil {
		return nil, err
	}

	var bvsr www.BatchVoteSummaryReply
	err = json.Unmarshal(responseBody, &bvsr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal BatchVoteSummary: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(bvsr)
		if err != nil {
			return nil, err
		}
	}

	return &bvsr, nil
}

// GetAllVetted retrieves a page of vetted proposals.
func (c *Client) GetAllVetted(gav *www.GetAllVetted) (*www.GetAllVettedReply, error) {
	responseBody, err := c.makeRequest(http.MethodGet,
		www.PoliteiaWWWAPIRoute, www.RouteAllVetted, gav)
	if err != nil {
		return nil, err
	}

	var gavr www.GetAllVettedReply
	err = json.Unmarshal(responseBody, &gavr)
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

// NewComment submits a new proposal comment for the logged in user.
func (c *Client) NewComment(nc *www.NewComment) (*www.NewCommentReply, error) {
	responseBody, err := c.makeRequest(http.MethodPost,
		www.PoliteiaWWWAPIRoute, www.RouteNewComment, nc)
	if err != nil {
		return nil, err
	}

	var ncr www.NewCommentReply
	err = json.Unmarshal(responseBody, &ncr)
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

// GetComments retrieves the comments for the specified proposal.
func (c *Client) GetComments(token string) (*www.GetCommentsReply, error) {
	route := "/proposals/" + token + "/comments"
	responseBody, err := c.makeRequest(http.MethodGet,
		www.PoliteiaWWWAPIRoute, route, nil)
	if err != nil {
		return nil, err
	}

	var gcr www.GetCommentsReply
	err = json.Unmarshal(responseBody, &gcr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal GetCommentsReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(gcr)
		if err != nil {
			return nil, err
		}
	}

	return &gcr, nil
}

// GetComments retrieves the comments for the specified proposal.
func (c *Client) InvoiceComments(token string) (*www.GetCommentsReply, error) {
	route := "/invoices/" + token + "/comments"
	responseBody, err := c.makeRequest(http.MethodGet,
		cms.APIRoute, route, nil)
	if err != nil {
		return nil, err
	}

	var gcr www.GetCommentsReply
	err = json.Unmarshal(responseBody, &gcr)
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

// UserCommentsLikes retrieves the comment likes (upvotes/downvotes) for the
// specified proposal that are from the logged in user.
func (c *Client) UserCommentsLikes(token string) (*www.UserCommentsLikesReply, error) {
	route := "/user/proposals/" + token + "/commentslikes"
	responseBody, err := c.makeRequest(http.MethodGet,
		www.PoliteiaWWWAPIRoute, route, nil)
	if err != nil {
		return nil, err
	}

	var uclr www.UserCommentsLikesReply
	err = json.Unmarshal(responseBody, &uclr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal UserCommentsLikesReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(uclr)
		if err != nil {
			return nil, err
		}
	}

	return &uclr, nil
}

// LikeComment casts a like comment action (upvote/downvote) for the logged in
// user.
func (c *Client) LikeComment(lc *www.LikeComment) (*www.LikeCommentReply, error) {
	responseBody, err := c.makeRequest(http.MethodPost,
		www.PoliteiaWWWAPIRoute, www.RouteLikeComment, lc)
	if err != nil {
		return nil, err
	}

	var lcr www.LikeCommentReply
	err = json.Unmarshal(responseBody, &lcr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal LikeCommentReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(lcr)
		if err != nil {
			return nil, err
		}
	}

	return &lcr, nil
}

// CensorComment censors the specified proposal comment.
func (c *Client) CensorComment(cc *www.CensorComment) (*www.CensorCommentReply, error) {
	responseBody, err := c.makeRequest(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteCensorComment, cc)
	if err != nil {
		return nil, err
	}

	var ccr www.CensorCommentReply
	err = json.Unmarshal(responseBody, &ccr)
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

// StartVoteV2 sends the provided v2 StartVote to the politeiawww backend.
func (c *Client) StartVoteV2(sv www2.StartVote) (*www2.StartVoteReply, error) {
	responseBody, err := c.makeRequest(http.MethodPost,
		www2.APIRoute, www2.RouteStartVote, sv)
	if err != nil {
		return nil, err
	}

	var svr www2.StartVoteReply
	err = json.Unmarshal(responseBody, &svr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal StartVoteReply: %v", err)
	}

	if c.cfg.Verbose {
		svr.EligibleTickets = []string{"removed by piwww for readability"}
		err := prettyPrintJSON(svr)
		if err != nil {
			return nil, err
		}
	}

	return &svr, nil
}

// VerifyUserPayment checks whether the logged in user has paid their user
// registration fee.
func (c *Client) VerifyUserPayment() (*www.VerifyUserPaymentReply, error) {
	responseBody, err := c.makeRequest(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteVerifyUserPayment, nil)
	if err != nil {
		return nil, err
	}

	var vupr www.VerifyUserPaymentReply
	err = json.Unmarshal(responseBody, &vupr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal VerifyUserPaymentReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(vupr)
		if err != nil {
			return nil, err
		}
	}

	return &vupr, nil
}

// VoteResults retrieves the vote results for the specified proposal.
func (c *Client) VoteResults(token string) (*www.VoteResultsReply, error) {
	route := "/proposals/" + token + "/votes"
	responseBody, err := c.makeRequest(http.MethodGet,
		www.PoliteiaWWWAPIRoute, route, nil)
	if err != nil {
		return nil, err
	}

	var vrr www.VoteResultsReply
	err = json.Unmarshal(responseBody, &vrr)
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
	respBody, err := c.makeRequest(http.MethodGet, www2.APIRoute, route, nil)
	if err != nil {
		return nil, err
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
	responseBody, err := c.makeRequest(http.MethodGet,
		www.PoliteiaWWWAPIRoute, route, nil)
	if err != nil {
		return nil, err
	}

	var udr www.UserDetailsReply
	err = json.Unmarshal(responseBody, &udr)
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
	responseBody, err := c.makeRequest(http.MethodGet,
		www.PoliteiaWWWAPIRoute, www.RouteUsers, u)
	if err != nil {
		return nil, err
	}

	var ur www.UsersReply
	err = json.Unmarshal(responseBody, &ur)
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
	responseBody, err := c.makeRequest(http.MethodGet, cms.APIRoute,
		cms.RouteCMSUsers, cu)
	if err != nil {
		return nil, err
	}

	var cur cms.CMSUsersReply
	err = json.Unmarshal(responseBody, &cur)
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
	responseBody, err := c.makeRequest(http.MethodPost,
		www.PoliteiaWWWAPIRoute, www.RouteManageUser, mu)
	if err != nil {
		return nil, err
	}

	var mur www.ManageUserReply
	err = json.Unmarshal(responseBody, &mur)
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
	responseBody, err := c.makeRequest(http.MethodPost,
		www.PoliteiaWWWAPIRoute, www.RouteEditUser, eu)
	if err != nil {
		return nil, err
	}

	var eur www.EditUserReply
	err = json.Unmarshal(responseBody, &eur)
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

// AuthorizeVote authorizes the voting period for the specified proposal using
// the logged in user.
func (c *Client) AuthorizeVote(av *www.AuthorizeVote) (*www.AuthorizeVoteReply, error) {
	responseBody, err := c.makeRequest(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteAuthorizeVote, av)
	if err != nil {
		return nil, err
	}

	var avr www.AuthorizeVoteReply
	err = json.Unmarshal(responseBody, &avr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal AuthorizeVoteReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(avr)
		if err != nil {
			return nil, err
		}
	}

	return &avr, nil
}

// VoteStatus retrieves the vote status for the specified proposal.
func (c *Client) VoteStatus(token string) (*www.VoteStatusReply, error) {
	route := "/proposals/" + token + "/votestatus"
	responseBody, err := c.makeRequest(http.MethodGet,
		www.PoliteiaWWWAPIRoute, route, nil)
	if err != nil {
		return nil, err
	}

	var vsr www.VoteStatusReply
	err = json.Unmarshal(responseBody, &vsr)
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
	responseBody, err := c.makeRequest(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteAllVoteStatus, nil)
	if err != nil {
		return nil, err
	}

	var avsr www.GetAllVoteStatusReply
	err = json.Unmarshal(responseBody, &avsr)
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

// ActiveVotes retreives all proposals that are currently being voted on.
func (c *Client) ActiveVotes() (*www.ActiveVoteReply, error) {
	responseBody, err := c.makeRequest(http.MethodGet,
		www.PoliteiaWWWAPIRoute, www.RouteActiveVote, nil)
	if err != nil {
		return nil, err
	}

	var avr www.ActiveVoteReply
	err = json.Unmarshal(responseBody, &avr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ActiveVoteReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(avr)
		if err != nil {
			return nil, err
		}
	}

	return &avr, nil
}

// CastVotes casts votes for a proposal.
func (c *Client) CastVotes(b *www.Ballot) (*www.BallotReply, error) {
	responseBody, err := c.makeRequest(http.MethodPost,
		www.PoliteiaWWWAPIRoute, www.RouteCastVotes, &b)
	if err != nil {
		return nil, err
	}

	var br www.BallotReply
	err = json.Unmarshal(responseBody, &br)
	if err != nil {
		return nil, fmt.Errorf("unmarshal BallotReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(br)
		if err != nil {
			return nil, err
		}
	}

	return &br, nil
}

// UpdateUserKey updates the identity of the logged in user.
func (c *Client) UpdateUserKey(uuk *www.UpdateUserKey) (*www.UpdateUserKeyReply, error) {
	responseBody, err := c.makeRequest(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteUpdateUserKey, &uuk)
	if err != nil {
		return nil, err
	}

	var uukr www.UpdateUserKeyReply
	err = json.Unmarshal(responseBody, &uukr)
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
	responseBody, err := c.makeRequest(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteVerifyUpdateUserKey, &vuuk)
	if err != nil {
		return nil, err
	}

	var vuukr www.VerifyUpdateUserKeyReply
	err = json.Unmarshal(responseBody, &vuukr)
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

// ProposalPaywallPayment retrieves payment details of any pending proposal
// credit payment from the logged in user.
func (c *Client) ProposalPaywallPayment() (*www.ProposalPaywallPaymentReply, error) {
	responseBody, err := c.makeRequest(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteProposalPaywallPayment, nil)
	if err != nil {
		return nil, err
	}

	var pppr www.ProposalPaywallPaymentReply
	err = json.Unmarshal(responseBody, &pppr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ProposalPaywallPaymentReply: %v", err)
	}

	if c.cfg.Verbose {
		err := prettyPrintJSON(pppr)
		if err != nil {
			return nil, err
		}
	}

	return &pppr, nil
}

// UserPaymentsRescan scans the specified user's paywall address and makes sure
// that the user's account has been properly credited with all payments.
func (c *Client) UserPaymentsRescan(upr *www.UserPaymentsRescan) (*www.UserPaymentsRescanReply, error) {
	responseBody, err := c.makeRequest(http.MethodPut, www.PoliteiaWWWAPIRoute,
		www.RouteUserPaymentsRescan, upr)
	if err != nil {
		return nil, err
	}

	var uprr www.UserPaymentsRescanReply
	err = json.Unmarshal(responseBody, &uprr)
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
	responseBody, err := c.makeRequest(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteUserProposalCredits, nil)
	if err != nil {
		return nil, err
	}

	var upcr www.UserProposalCreditsReply
	err = json.Unmarshal(responseBody, &upcr)
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
	respBody, err := c.makeRequest(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteResendVerification, rv)
	if err != nil {
		return nil, err
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
func (c *Client) InvoiceDetails(token string) (*cms.InvoiceDetailsReply, error) {
	route := "/invoices/" + token
	responseBody, err := c.makeRequest(http.MethodGet, cms.APIRoute, route, nil)
	if err != nil {
		return nil, err
	}

	var idr cms.InvoiceDetailsReply
	err = json.Unmarshal(responseBody, &idr)
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
	responseBody, err := c.makeRequest(http.MethodPost,
		cms.APIRoute, route, sis)
	if err != nil {
		return nil, err
	}

	var sisr cms.SetInvoiceStatusReply
	err = json.Unmarshal(responseBody, &sisr)
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
	responseBody, err := c.makeRequest(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteTokenInventory, nil)
	if err != nil {
		return nil, err
	}

	var tir www.TokenInventoryReply
	err = json.Unmarshal(responseBody, &tir)
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
	responseBody, err := c.makeRequest(http.MethodPost,
		cms.APIRoute, cms.RouteInvoiceExchangeRate, ier)
	if err != nil {
		return nil, err
	}

	var ierr cms.InvoiceExchangeRateReply
	err = json.Unmarshal(responseBody, &ierr)
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
	responseBody, err := c.makeRequest(http.MethodPost,
		cms.APIRoute, cms.RouteInvoicePayouts, lip)
	if err != nil {
		return nil, err
	}

	var lipr cms.InvoicePayoutsReply
	err = json.Unmarshal(responseBody, &lipr)
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
	responseBody, err := c.makeRequest(http.MethodGet, cms.APIRoute, route, nil)
	if err != nil {
		return nil, err
	}

	var uir cms.UserDetailsReply
	err = json.Unmarshal(responseBody, &uir)
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
	responseBody, err := c.makeRequest(http.MethodPost,
		cms.APIRoute, www.RouteEditUser, uui)
	if err != nil {
		return nil, err
	}

	var eur cms.EditUserReply
	err = json.Unmarshal(responseBody, &eur)
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
	responseBody, err := c.makeRequest(http.MethodPost, cms.APIRoute,
		cms.RouteManageCMSUser, uui)
	if err != nil {
		return nil, err
	}

	var eur cms.CMSManageUserReply
	err = json.Unmarshal(responseBody, &eur)
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
	responseBody, err := c.makeRequest(http.MethodPost,
		cms.APIRoute, cms.RouteNewDCC, nd)
	if err != nil {
		return nil, err
	}

	var ndr cms.NewDCCReply
	err = json.Unmarshal(responseBody, &ndr)
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
	responseBody, err := c.makeRequest(http.MethodPost,
		cms.APIRoute, cms.RouteSupportOpposeDCC, sd)
	if err != nil {
		return nil, err
	}

	var sdr cms.SupportOpposeDCCReply
	err = json.Unmarshal(responseBody, &sdr)
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
	responseBody, err := c.makeRequest(http.MethodPost,
		cms.APIRoute, cms.RouteNewCommentDCC, nc)
	if err != nil {
		return nil, err
	}

	var ncr www.NewCommentReply
	err = json.Unmarshal(responseBody, &ncr)
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
	responseBody, err := c.makeRequest(http.MethodGet, cms.APIRoute, route, nil)
	if err != nil {
		return nil, err
	}

	var gcr www.GetCommentsReply
	err = json.Unmarshal(responseBody, &gcr)
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
	responseBody, err := c.makeRequest(http.MethodGet, cms.APIRoute, route, nil)
	if err != nil {
		return nil, err
	}

	var ddr cms.DCCDetailsReply
	err = json.Unmarshal(responseBody, &ddr)
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

// GetDCCss retrieves invoices base on possible field set in the request
// month/year and/or status
func (c *Client) GetDCCs(gd *cms.GetDCCs) (*cms.GetDCCsReply, error) {
	responseBody, err := c.makeRequest(http.MethodPost,
		cms.APIRoute, cms.RouteGetDCCs, gd)
	if err != nil {
		return nil, err
	}

	var gdr cms.GetDCCsReply
	err = json.Unmarshal(responseBody, &gdr)
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
	responseBody, err := c.makeRequest(http.MethodPost, cms.APIRoute, route, sd)
	if err != nil {
		return nil, err
	}

	var sdr cms.SetDCCStatusReply
	err = json.Unmarshal(responseBody, &sdr)
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
	responseBody, err := c.makeRequest(http.MethodGet,
		cms.APIRoute, cms.RouteUserSubContractors, usc)
	if err != nil {
		return nil, err
	}

	var uscr cms.UserSubContractorsReply
	err = json.Unmarshal(responseBody, &uscr)
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
	responseBody, err := c.makeRequest(http.MethodGet,
		cms.APIRoute, cms.RouteProposalOwner, po)
	if err != nil {
		return nil, err
	}

	var por cms.ProposalOwnerReply
	err = json.Unmarshal(responseBody, &por)
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

// New returns a new politeiawww client.
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
