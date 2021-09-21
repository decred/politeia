// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

func TestReqBodySizeMiddleware(t *testing.T) {
	// Setup the test router
	router := mux.NewRouter()
	m := middleware{
		reqBodySizeLimit: 5,
	}
	router.Use(closeBodyMiddleware)
	router.Use(m.reqBodySizeLimitMiddleware)

	// Setup a route handler that reads the request body. Reading
	// the request body is required in order to trigger the error.
	testRoute := "/test"
	router.HandleFunc(testRoute, func(w http.ResponseWriter, r *http.Request) {
		_, err := ioutil.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	// Setup test request bodies
	const (
		fourBytes = "1234"
		fiveBytes = "12345"
		sixBytes  = "123456"
	)

	// Setup tests
	var tests = []struct {
		name     string
		reqBody  string
		wantCode int
	}{
		{
			"no request body",
			"",
			http.StatusOK,
		},
		{
			"under the req body limit",
			fourBytes,
			http.StatusOK,
		},
		{
			"at the req body limit",
			fiveBytes,
			http.StatusOK,
		},
		{
			"over the req body limit",
			sixBytes,
			http.StatusBadRequest,
		},
	}

	// Run tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup the test request
			req, err := http.NewRequest(http.MethodPost,
				testRoute, strings.NewReader(tc.reqBody))
			if err != nil {
				t.Fatal(err)
			}

			// Send the test request
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			// Verify the response
			if rr.Code != tc.wantCode {
				t.Errorf("wrong http response code: got %v, want %v",
					rr.Code, tc.wantCode)
			}
		})
	}
}
