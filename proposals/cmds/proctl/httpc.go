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
	"time"

	"github.com/gorilla/schema"
	"golang.org/x/net/publicsuffix"
)

// httpc provides a client for interacting with the politeia http API.
type httpc struct {
	host *url.URL
	http *http.Client
}

// httpcOpts contains the optional http client settings.
type httpcOpts struct {
	CertPool *x509.CertPool
	Cookies  []*http.Cookie
}

// newHttpc returns a new httpc.
func newHttpc(host *url.URL, opts *httpcOpts) (*httpc, error) {
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
	if opts.Cookies != nil {
		copt := cookiejar.Options{
			PublicSuffixList: publicsuffix.List,
		}
		jar, err := cookiejar.New(&copt)
		if err != nil {
			return nil, err
		}
		jar.SetCookies(host, opts.Cookies)
		h.Jar = jar
	}

	return &httpc{
		host: host,
		http: h,
	}, nil
}

// serverReply represents a reply from the server.
type serverReply struct {
	HTTPCode int
	Body     []byte
}

// sendReq sends a http request to the method and route provided.
//
// The req data is encoded as query params if the request is a GET request. The
// req data is included as a JSON encoded request body for all other request
// types.
//
// The HTTP status code and the serialized response body are returned in the
// serverReply.
func (c *httpc) sendReq(method string, route string, reqData interface{}) (*serverReply, error) {
	// Setup the request data
	var (
		reqBody     []byte
		queryParams string
		err         error
	)
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
			queryParams = "?" + form.Encode()

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

	// Setup the route
	fullRoute := c.host.String() + route + queryParams

	// Print the request details
	log.Debugf("Request: %v %v", method, fullRoute)
	if len(reqBody) > 0 {
		log.Debugf("%s", reqBody)
	}

	// Send request
	req, err := http.NewRequest(method, fullRoute, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
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

	// Print the response details
	log.Debugf("Response: %v", r.StatusCode)
	log.Debugf("%s", respBody)

	return &serverReply{
		HTTPCode: r.StatusCode,
		Body:     respBody,
	}, nil
}
