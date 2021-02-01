// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"reflect"

	"github.com/decred/politeia/util"
	"github.com/gorilla/schema"
	"golang.org/x/net/publicsuffix"
)

var (
	headerCSRF = "X-CSRF-Token"
)

// Client provides a client for interacting with the politeiawww API.
type Client struct {
	host       string
	cert       string
	headerCSRF string // Header csrf token
	http       *http.Client
}

// ErrorReply represents the request body that is returned from politeiawww
// when an error occurs. PluginID will only be populated if the error occured
// during execution of a plugin command.
type ErrorReply struct {
	PluginID     string
	ErrorCode    int
	ErrorContext string
}

// httpsError represents a politeiawww error. Error is returned anytime the
// politeiawww response is not a 200.
type Error struct {
	HTTPCode   int
	ErrorReply ErrorReply
}

// Error satisfies the error interface.
func (e Error) Error() string {
	switch {
	case e.HTTPCode == http.StatusNotFound:
		return fmt.Sprintf("404 not found")
	case e.ErrorReply.PluginID != "":
		return fmt.Sprintf("politeiawww plugin error: %v %v %v",
			e.HTTPCode, e.ErrorReply.PluginID, e.ErrorReply.ErrorCode)
	default:
		return fmt.Sprintf("politeiawww error: %v %v",
			e.HTTPCode, e.ErrorReply.ErrorCode)
	}
}

// makeReq makes a politeiawww http request to the method and route provided,
// serializing the provided object as the request body, and returning a byte
// slice of the repsonse body. An Error is returned if politeiawww responds
// with anything other than a 200 http status code.
func (c *Client) makeReq(method string, route string, v interface{}) ([]byte, error) {
	// Serialize body
	var (
		reqBody     []byte
		queryParams string
		err         error
	)
	if v != nil {
		switch method {
		case http.MethodGet:
			// Use reflection in case the interface value is nil but the
			// interface type is not. This can happen when query params
			// exist but are not used.
			if reflect.ValueOf(v).IsNil() {
				break
			}

			// Populate GET request query params
			form := url.Values{}
			if err := schema.NewEncoder().Encode(v, form); err != nil {
				return nil, err
			}
			queryParams = "?" + form.Encode()

		case http.MethodPost, http.MethodPut:
			reqBody, err = json.Marshal(v)
			if err != nil {
				return nil, err
			}

		default:
			return nil, fmt.Errorf("unknown http method '%v'", method)
		}
	}

	// Send request
	fullRoute := c.host + route + queryParams
	req, err := http.NewRequest(method, fullRoute, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	if c.headerCSRF != "" {
		req.Header.Add(headerCSRF, c.headerCSRF)
	}
	r, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	// Handle reply
	if r.StatusCode != http.StatusOK {
		var e ErrorReply
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&e); err != nil {
			return nil, fmt.Errorf("status code %v: %v", r.StatusCode, err)
		}
		return nil, Error{
			HTTPCode:   r.StatusCode,
			ErrorReply: e,
		}
	}

	respBody := util.ConvertBodyToByteArray(r.Body, false)
	return respBody, nil
}

// New returns a new politeiawww client.
//
// The cert argument is optional. Any provided cert will be added to the http
// client's trust cert pool. This allows you to interact with a politeiawww
// instance that uses a self signed cert.
//
// The cookies and headerCSRF arguments are optional.
func New(host, cert string, cookies []*http.Cookie, headerCSRF string) (*Client, error) {
	// Setup http client
	h, err := util.NewHTTPClient(false, cert)
	if err != nil {
		return nil, err
	}

	// Setup cookies
	if cookies != nil {
		opt := cookiejar.Options{
			PublicSuffixList: publicsuffix.List,
		}
		jar, err := cookiejar.New(&opt)
		if err != nil {
			return nil, err
		}
		u, err := url.Parse(host)
		if err != nil {
			return nil, err
		}
		jar.SetCookies(u, cookies)
		h.Jar = jar
	}

	return &Client{
		host:       host,
		cert:       cert,
		headerCSRF: headerCSRF,
		http:       h,
	}, nil
}
