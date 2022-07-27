// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	auth "github.com/decred/politeia/plugins/auth/v1"
	v3 "github.com/decred/politeia/politeiawww/api/http/v3"
	"github.com/gorilla/schema"
	"github.com/pkg/errors"
	"golang.org/x/net/publicsuffix"
)

// httpc provides a http client for interacting with the politeia API.
type httpc struct {
	host *url.URL
	http *http.Client
	db   *kvdb
}

// httpcOpts contains the optional httpc settings.
type httpcOpts struct {
	CertPool *x509.CertPool
	Cookies  []*http.Cookie
}

// newHttpc returns a new httpc.
func newHttpc(host *url.URL, db *kvdb, opts *httpcOpts) (*httpc, error) {
	if opts == nil {
		opts = &httpcOpts{}
	}

	// Setup the http client
	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
	}
	if opts.CertPool != nil {
		tlsConfig.RootCAs = opts.CertPool
	}
	h := &http.Client{
		Timeout: 2 * time.Minute,
		Transport: &http.Transport{
			IdleConnTimeout:       2 * time.Minute,
			ResponseHeaderTimeout: 2 * time.Minute,
			TLSClientConfig:       tlsConfig,
		},
	}

	// Setup the cookies
	copts := &cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	}
	jar, err := cookiejar.New(copts)
	if err != nil {
		return nil, err
	}
	jar.SetCookies(host, opts.Cookies)
	h.Jar = jar

	return &httpc{
		host: host,
		http: h,
		db:   db,
	}, nil
}

// serverReply represents a reply from the server.
type serverReply struct {
	HTTPCode int
	Body     []byte

	// Header contains all of the response headers.
	Header http.Header

	// SetCookies contains the cookies that the server returned in the
	// Set-Cookie header.
	SetCookies []*http.Cookie
}

// sendReq prepares and sends a http request.
//
// The req data is encoded as query params if the request is a GET request. The
// req data is included as a JSON encoded request body for all other request
// types.
//
// The HTTP status code and the serialized response body are returned in the
// serverReply.
func (c *httpc) sendReq(method string, route string, reqData interface{}, headers map[string]string) (*serverReply, error) {
	// Setup the request URL
	reqURL, err := url.Parse(route)
	if err != nil {
		return nil, err
	}
	var reqBody []byte
	if reqData != nil {
		switch method {
		case http.MethodGet:
			// Use reflection in case the interface value
			// is nil but the interface type is not. This
			// can happen when query params exist but are
			// not used.
			if reflect.ValueOf(reqData).IsNil() {
				break
			}

			// Populate the query params
			form := url.Values{}
			err := schema.NewEncoder().Encode(reqData, form)
			if err != nil {
				return nil, err
			}
			reqURL.RawQuery = form.Encode()

		case http.MethodPost, http.MethodPut:
			// Prepare the request body
			reqBody, err = json.Marshal(reqData)
			if err != nil {
				return nil, err
			}

		default:
			return nil, fmt.Errorf("unknown http method '%v'", method)
		}
	}

	// Setup the request
	req, err := http.NewRequest(method, reqURL.String(),
		bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Add(k, v)
	}
	for _, v := range c.http.Jar.Cookies(c.host) {
		if v.Value == "" {
			// The cookie value is empty. This will
			// tell the client to delete the cookie.
			v.MaxAge = -1
			c.http.Jar.SetCookies(c.host, []*http.Cookie{v})
		}
	}

	log.Debugf("%v", reqStr(req, c.http.Jar.Cookies(c.host), reqBody))

	// Send the request
	r, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	var b bytes.Buffer
	w := io.MultiWriter(&b)
	io.Copy(w, r.Body)
	respBody := b.Bytes()

	log.Debugf(respStr(r, respBody))

	return &serverReply{
		HTTPCode:   r.StatusCode,
		Body:       respBody,
		Header:     r.Header,
		SetCookies: r.Cookies(),
	}, nil
}

// sendReqV3 sends a request to the v3 politeia http API.
func (c *httpc) sendReqV3(method string, route string, reqData interface{}) ([]byte, error) {
	route = fmt.Sprintf("%v%v%v", c.host.String(), v3.APIVersionPrefix, route)

	// Setup the cookies
	cookies, err := c.getCookies()
	if err != nil {
		return nil, err
	}
	c.http.Jar.SetCookies(c.host, cookies)

	// Setup the CSRF header token
	csrf, err := c.getCSRF()
	if err != nil {
		return nil, err
	}
	var headers map[string]string
	if csrf != "" {
		headers = map[string]string{
			v3.CSRFTokenHeader: csrf,
		}
	}

	// Send the request
	r, err := c.sendReq(method, route, reqData, headers)
	if err != nil {
		return nil, err
	}
	switch r.HTTPCode {
	case http.StatusOK:
		// Expected reply; continue

	case http.StatusBadRequest:
		var e v3.UserError
		err = json.Unmarshal(r.Body, &e)
		if err != nil {
			return nil, err
		}
		errStr := v3.ErrCodes[e.ErrorCode]
		if e.ErrorContext == "" {
			err = errors.Errorf("user error: %v", errStr)
		} else {
			err = errors.Errorf("user error: %v - %v", errStr, e.ErrorContext)
		}
		return nil, err

	case http.StatusForbidden:
		return nil, errors.Errorf("%v %sRun the 'version' command to "+
			"get a new CSRF token from the server", r.HTTPCode, r.Body)

	default:
		return nil, errors.Errorf("unexpected server response: %v %s",
			r.HTTPCode, r.Body)
	}

	// Save the header CSRF token to the database
	csrf = r.Header.Get(v3.CSRFTokenHeader)
	if csrf != "" {
		err := c.saveCSRF(csrf)
		if err != nil {
			return nil, err
		}
	}

	// Update the cookies and save them to the database
	if len(r.SetCookies) > 0 {
		c.http.Jar.SetCookies(c.host, r.SetCookies)
		err = c.saveCookies(c.http.Jar.Cookies(c.host))
		if err != nil {
			return nil, err
		}
	}

	return r.Body, nil
}

// Versions sends a GET request to the politeia v3 VersionRoute.
func (c *httpc) Version() (*v3.VersionReply, error) {
	b, err := c.sendReqV3(http.MethodGet, v3.VersionRoute, nil)
	if err != nil {
		return nil, err
	}
	var r v3.VersionReply
	err = json.Unmarshal(b, &r)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *httpc) Policy() (*v3.PolicyReply, error) {
	b, err := c.sendReqV3(http.MethodGet, v3.PolicyRoute, nil)
	if err != nil {
		return nil, err
	}
	var r v3.PolicyReply
	err = json.Unmarshal(b, &r)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *httpc) WriteCmd(cmd v3.Cmd) (*v3.CmdReply, error) {
	b, err := c.sendReqV3(http.MethodPost, v3.WriteRoute, cmd)
	if err != nil {
		return nil, err
	}
	var r v3.CmdReply
	err = json.Unmarshal(b, &r)
	if err != nil {
		return nil, err
	}
	if r.Error != nil {
		return nil, pluginErr{
			Plugin:  r.Plugin,
			Code:    r.Error.Code,
			Context: r.Error.Context,
		}
	}
	return &r, nil
}

func (c *httpc) saveCookies(cs []*http.Cookie) error {
	b, err := json.Marshal(cs)
	if err != nil {
		return err
	}
	err = c.db.Put(map[string][]byte{
		c.cookiesKey(): b,
	})

	log.Debugf("Cookies saved to the db")

	return nil
}

func (c *httpc) getCookies() ([]*http.Cookie, error) {
	b, err := c.db.Get(c.cookiesKey())
	if err != nil {
		if errors.Is(err, errNotFound) {
			return []*http.Cookie{}, nil
		}
		return nil, err
	}
	var cs []*http.Cookie
	err = json.Unmarshal(b, &cs)
	if err != nil {
		return nil, err
	}
	return cs, nil
}

func (c *httpc) cookiesKey() string {
	return fmt.Sprintf("%v-cookies", c.host.String())
}

func (c *httpc) saveCSRF(csrfHeaderToken string) error {
	err := c.db.Put(map[string][]byte{
		c.csrfKey(): []byte(csrfHeaderToken),
	})
	if err != nil {
		return err
	}

	log.Debugf("Header CSRF token saved to the db")

	return nil
}

func (c *httpc) getCSRF() (string, error) {
	b, err := c.db.Get(c.csrfKey())
	if err != nil {
		if errors.Is(err, errNotFound) {
			return "", nil
		}
		return "", err
	}
	return string(b), nil
}

func (c *httpc) csrfKey() string {
	return fmt.Sprintf("%v-csrf", c.host.String())
}

// reqStr returns a multi line string that contains request details that are
// useful for debugging. An example string is shown below.
//
// HTTP request
//   URL       : GET https://localhost:4443/v3/version
//   Body      :
//   Header    : X-Csrf-Token 9kx8fS2MGuTa27xN41rlXhCUwob2+O/Hxx4GdzWgCWd46r3B
//   Cookie    : _gorilla_csrf=MTY1ODcwMTY2MHxJbXB4WWtKMlVGTlZPVk14UzFGUmFsTmt
func reqStr(r *http.Request, cookies []*http.Cookie, body []byte) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("HTTP request\n"))
	b.WriteString(fmt.Sprintf("  URL       : %v %v\n", r.Method, r.URL.String()))
	b.WriteString(fmt.Sprintf("  Body      : %s\n", body))
	for k, v := range r.Header {
		if !strings.HasPrefix(k, "X-") {
			continue
		}
		b.WriteString(fmt.Sprintf("  Header    : %v %v\n",
			k, strings.Join(v, ",")))
	}
	for _, ck := range cookies {
		b.WriteString(fmt.Sprintf("  Cookie    : %v\n", ck.String()))
	}

	// Trim the last newline
	s := b.String()
	if strings.HasSuffix(s, "\n") {
		s = s[:len(s)-1]
	}

	return s
}

// respStr returns a multi line string that contains response details that are
// useful for debugging. An example string is shown below.
//
// HTTP response
//   Status    : 200
//   Body      :
//   Header    : X-Csrf-Token hMboCj1C8+JzEvbxpGcWgQjq4UWS4bMuOLgKDXQjW6kxnoVt
//   Header    : X-Frame-Options DENY
//   Header    : X-Xss-Protection 1; mode=block
//   Header    : X-Content-Type-Options nosniff
//   Set-Cookie: _gorilla_csrf=MTY1ODc2MTc3M3xJblJXYUhSYU1GWkVWM1JoTlM5UVVtcHs
func respStr(r *http.Response, body []byte) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("HTTP response\n"))
	b.WriteString(fmt.Sprintf("  Status    : %v\n", r.StatusCode))
	b.WriteString(fmt.Sprintf("  Body      : %s\n", body))
	for k, v := range r.Header {
		if !strings.HasPrefix(k, "X-") {
			continue
		}
		b.WriteString(fmt.Sprintf("  Header    : %v %v\n",
			k, strings.Join(v, ",")))
	}
	for _, ck := range r.Cookies() {
		b.WriteString(fmt.Sprintf("  Set-Cookie: %v", ck.String()))
	}

	// Trim the last newline
	s := b.String()
	if strings.HasSuffix(s, "\n") {
		s = s[:len(s)-1]
	}

	return s
}

type pluginErr struct {
	Plugin  string
	Code    uint32
	Context string
}

func (e pluginErr) Error() string {
	var errStr string
	switch e.Plugin {
	case auth.PluginID:
		errStr = auth.ErrCodes[auth.ErrCode(e.Code)]
	default:
		errStr = strconv.FormatUint(uint64(e.Code), 10)
	}
	if e.Context == "" {
		return fmt.Sprintf("%v plugin err: %v", e.Plugin, errStr)
	}
	return fmt.Sprintf("%v plugin err: %v - %v", e.Plugin, errStr, e.Context)
}
