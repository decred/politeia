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
	"time"

	auth "github.com/decred/politeia/plugins/auth/v1"
	v3 "github.com/decred/politeia/politeiawww/api/http/v3"
	"github.com/gorilla/schema"
	"github.com/pkg/errors"
	"golang.org/x/net/publicsuffix"
)

// httpc provides a client for interacting with the politeia http API.
type httpc struct {
	host *url.URL
	http *http.Client
	db   *kvdb
}

// httpcOpts contains the optional http client settings.
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

	// Add any provided cookies to the client
	copt := cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	}
	jar, err := cookiejar.New(&copt)
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
	Headers  map[string]string
	Cookies  []*http.Cookie
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
			// JSON encode the req data
			reqBody, err = json.Marshal(reqData)
			if err != nil {
				return nil, err
			}

		default:
			return nil, fmt.Errorf("unknown http method '%v'", method)
		}
	}

	log.Debugf("Request : %v %v", method, reqURL.String())
	log.Debugf("Body    : %s", reqBody)
	for k, v := range headers {
		log.Debugf("Header  : %v %v", k, v)
	}
	if c.http.Jar != nil {
		log.Debugf("Cookies : %+v", c.http.Jar.Cookies(c.host))
	}

	// Setup and send the request
	req, err := http.NewRequest(method, reqURL.String(),
		bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Add(k, v)
	}
	r, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	var b bytes.Buffer
	mw := io.MultiWriter(&b)
	io.Copy(mw, r.Body)
	respBody := b.Bytes()

	log.Debugf("Response: %v", r.StatusCode)
	log.Debugf("Body    : %s", respBody)
	respHeaders := make(map[string]string, 64)
	for k := range headers {
		v := r.Header.Get(k)
		if v == "" {
			continue
		}
		log.Debugf("Header   : %v %v", k, v)
		respHeaders[k] = v
	}
	log.Debugf("Cookies : %+v", r.Cookies())

	return &serverReply{
		HTTPCode: r.StatusCode,
		Body:     respBody,
		Cookies:  r.Cookies(),
		Headers:  respHeaders,
	}, nil
}

// sendReqV3 sends a request to the v3 politeia http API.
func (c *httpc) sendReqV3(method string, route string, reqData interface{}) ([]byte, error) {
	route = fmt.Sprintf("%v%v%v", c.host.String(), v3.APIVersionPrefix, route)

	// Setup any persisted cookies
	cookies, err := c.getCookies()
	if err != nil {
		return nil, err
	}
	c.http.Jar.SetCookies(c.host, cookies)

	// Setup the CSRF header token
	reqCSRF, err := c.getCSRF()
	if err != nil {
		return nil, err
	}
	headers := map[string]string{
		v3.CSRFTokenHeader: reqCSRF,
	}

	// Send the request
	sr, err := c.sendReq(method, route, reqData, headers)
	if err != nil {
		return nil, err
	}
	switch sr.HTTPCode {
	case http.StatusOK:
		// Expected reply; continue

	case http.StatusBadRequest:
		var e v3.UserError
		err = json.Unmarshal(sr.Body, &e)
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

	default:
		return nil, errors.Errorf("unexpected server response: %v %s",
			sr.HTTPCode, sr.Body)
	}

	// Save any returned cookies
	err = c.saveCookies(sr.Cookies)
	if err != nil {
		return nil, err
	}

	// Save the CSRF header token that was returned
	// if it's different than the one we're using.
	respCSRF := sr.Headers[v3.CSRFTokenHeader]
	if respCSRF != reqCSRF {
		c.saveCSRF(respCSRF)
	}

	return sr.Body, nil
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

	log.Debugf("Cookies saved")

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

	log.Debugf("CSRF header token saved")

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
