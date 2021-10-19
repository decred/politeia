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
	// HTTP headers
	headerCSRF = "X-CSRF-Token"
)

// Client provides a client for interacting with the politeiawww API.
type Client struct {
	host       string
	headerCSRF string // Header csrf token
	verbose    bool
	rawJSON    bool
	http       *http.Client
}

// makeReq makes a politeiawww http request to the method and route provided,
// serializing the provided object as the request body, and returning a byte
// slice of the response body. An ReqError is returned if politeiawww responds
// with anything other than a 200 http status code.
func (c *Client) makeReq(method string, api, route string, v interface{}) ([]byte, error) {
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

	// Setup route
	fullRoute := c.host + api + route + queryParams

	// Print request details
	switch {
	case method == http.MethodGet && c.verbose:
		fmt.Printf("Request: %v %v\n", method, fullRoute)
	case method == http.MethodGet && c.rawJSON:
		// No JSON to print
	case c.verbose:
		fmt.Printf("Request: %v %v\n", method, fullRoute)
		if len(reqBody) > 0 {
			fmt.Printf("%s\n", reqBody)
		}
	case c.rawJSON:
		if len(reqBody) > 0 {
			fmt.Printf("%s\n", reqBody)
		}
	}

	// Send request
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

	// Print response code
	if c.verbose {
		fmt.Printf("Response: %v\n", r.StatusCode)
	}

	// Handle reply
	if r.StatusCode != http.StatusOK {
		switch r.StatusCode {
		case http.StatusNotFound:
			return nil, fmt.Errorf("404 not found")
		case http.StatusForbidden:
			return nil, fmt.Errorf("403 %s", util.RespBody(r))
		default:
			// All other http status codes should have a request body that
			// decodes into a ErrorReply.
			var e ErrorReply
			decoder := json.NewDecoder(r.Body)
			if err := decoder.Decode(&e); err != nil {
				return nil, fmt.Errorf("status code %v: %v", r.StatusCode, err)
			}
			return nil, RespErr{
				HTTPCode:   r.StatusCode,
				API:        api,
				ErrorReply: e,
			}
		}
	}

	// Decode response body
	respBody := util.RespBody(r)

	// Print response body
	if c.verbose || c.rawJSON {
		fmt.Printf("%s\n", respBody)
	}

	return respBody, nil
}

// Opts contains the politeiawww client options. All values are optional.
//
// Any provided HTTPSCert will be added to the http client's trusted cert
// pool, allowing you to interact with a politeiawww instance that uses a
// self signed cert.
//
// Authenticated routes require a CSRF cookie as well as the corresponding
// CSRF header.
type Opts struct {
	HTTPSCert  string
	Cookies    []*http.Cookie
	HeaderCSRF string
	Verbose    bool // Print verbose output
	RawJSON    bool // Print raw json
}

// New returns a new politeiawww client.
func New(host string, opts Opts) (*Client, error) {
	// Setup http client
	h, err := util.NewHTTPClient(false, opts.HTTPSCert)
	if err != nil {
		return nil, err
	}

	// Setup cookies
	if opts.Cookies != nil {
		copt := cookiejar.Options{
			PublicSuffixList: publicsuffix.List,
		}
		jar, err := cookiejar.New(&copt)
		if err != nil {
			return nil, err
		}
		u, err := url.Parse(host)
		if err != nil {
			return nil, err
		}
		jar.SetCookies(u, opts.Cookies)
		h.Jar = jar
	}

	return &Client{
		host:       host,
		headerCSRF: opts.HeaderCSRF,
		verbose:    opts.Verbose,
		rawJSON:    opts.RawJSON,
		http:       h,
	}, nil
}
