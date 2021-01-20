// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/decred/politeia/util"
)

// pdErrorReply represents the request body that is returned from politeaid
// when an error occurs. PluginID will be populated if this is a plugin error.
type pdErrorReply struct {
	ErrorCode    int
	ErrorContext []string
	Plugin       string
}

// pdError represents a politeiad error.
type pdError struct {
	HTTPCode   int
	ErrorReply pdErrorReply
}

// Error satisfies the error interface.
func (e pdError) Error() string {
	return fmt.Sprintf("error from politeiad: %v %v",
		e.HTTPCode, e.ErrorReply.ErrorCode)
}

// makeRequest makes a politeiad http request to the method and route provided,
// serializing the provided object as the request body. A pdError is returned
// if politeiad does not respond with a 200.
//
// This method has been DEPRECATED. The politeiad client on the politeiawww
// context should be used instead. This method can be removed once all of the
// cms invocations have been switched over to use the politeaid client.
func (p *politeiawww) makeRequest(ctx context.Context, method string, route string, v interface{}) ([]byte, error) {
	var (
		reqBody []byte
		err     error
	)
	if v != nil {
		reqBody, err = json.Marshal(v)
		if err != nil {
			return nil, err
		}
	}

	fullRoute := p.cfg.RPCHost + route

	log.Debugf("%v %v", method, fullRoute)

	req, err := http.NewRequestWithContext(ctx, method,
		fullRoute, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(p.cfg.RPCUser, p.cfg.RPCPass)
	r, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		var e pdErrorReply
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&e); err != nil {
			return nil, fmt.Errorf("status code %v: %v", r.StatusCode, err)
		}

		return nil, pdError{
			HTTPCode:   r.StatusCode,
			ErrorReply: e,
		}
	}

	responseBody := util.ConvertBodyToByteArray(r.Body, false)
	return responseBody, nil
}
