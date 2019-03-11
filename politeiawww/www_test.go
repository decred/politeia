// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/decred/politeia/politeiad/api/v1/identity"
	v1 "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/gorilla/mux"
)

func TestHandleNewUser(t *testing.T) {
	p := newTestPoliteiawww(t)
	defer cleanupTestPoliteiawww(t, p)

	// Create an identity for the success test case
	id, err := identity.New()
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Setup tests
	var tests = []struct {
		name           string
		reqBody        interface{}
		wantStatusCode int
		wantError      error
	}{
		{"invalid input", "", http.StatusBadRequest,
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidInput,
			}},

		{"process new user error", v1.NewUser{}, http.StatusBadRequest,
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidPublicKey,
			}},

		{"new user success",
			v1.NewUser{
				Email:     "user@example.com",
				Password:  "password",
				PublicKey: hex.EncodeToString(id.Public.Key[:]),
				Username:  "user",
			},
			http.StatusOK, nil},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			// Setup request
			reqBody, err := json.Marshal(v.reqBody)
			if err != nil {
				t.Fatalf("%v", err)
			}
			r := httptest.NewRequest(http.MethodPost, v1.RouteNewUser,
				bytes.NewReader(reqBody))
			w := httptest.NewRecorder()

			// Run test case
			p.handleNewUser(w, r)
			res := w.Result()
			body, _ := ioutil.ReadAll(res.Body)

			// Validate response
			if res.StatusCode != v.wantStatusCode {
				t.Errorf("got status code %v, want %v",
					res.StatusCode, v.wantStatusCode)
			}

			if res.StatusCode == http.StatusOK {
				// No need to check for an error code
				// when the response status is a 200.
				return
			}

			var ue v1.UserError
			err = json.Unmarshal(body, &ue)
			if err != nil {
				t.Errorf("unmarshal UserError: %v", err)
			}

			got := errToStr(ue)
			want := errToStr(v.wantError)
			if got != want {
				t.Errorf("got error %v, want %v", got, want)
			}
		})
	}
}

func TestHandleVerifyNewUser(t *testing.T) {
	p := newTestPoliteiawww(t)
	defer cleanupTestPoliteiawww(t, p)

	// Create an unverified user to test against. We do this
	// by creating a verified user then manually reseting the
	// verification fields.
	usr, id := newUser(t, p, false)
	tb, expiry, err := p.generateVerificationTokenAndExpiry()
	if err != nil {
		t.Fatalf("%v", err)
	}
	usr.NewUserVerificationToken = tb
	usr.NewUserVerificationExpiry = expiry
	err = p.db.UserUpdate(*usr)
	if err != nil {
		t.Fatalf("%v", err)
	}
	token := hex.EncodeToString(tb)
	s := id.SignMessage([]byte(token))
	sig := hex.EncodeToString(s[:])

	// Test invalid input. We have to run it individually so that
	// we can set the wrong query param.
	t.Run("invalid input", func(t *testing.T) {
		// Setup request
		q := url.Values{}
		q.Set("hello", "world")
		route := fmt.Sprintf("%v?%v", v1.RouteVerifyNewUser, q.Encode())
		r := httptest.NewRequest(http.MethodGet, route, nil)
		w := httptest.NewRecorder()

		// Run test case
		p.handleVerifyNewUser(w, r)
		res := w.Result()
		body, _ := ioutil.ReadAll(res.Body)

		// Validate response
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("got status code %v, want %v",
				res.StatusCode, http.StatusBadRequest)
		}

		var ue v1.UserError
		err = json.Unmarshal(body, &ue)
		if err != nil {
			t.Errorf("unmarshal UserError: %v", err)
		}

		got := errToStr(ue)
		want := v1.ErrorStatus[v1.ErrorStatusInvalidInput]
		if got != want {
			t.Errorf("got error %v, want %v", got, want)
		}
	})

	// Setup remaining tests
	var tests = []struct {
		name           string
		params         v1.VerifyNewUser
		wantStatusCode int
		wantError      error
	}{
		{"process verify new user error",
			v1.VerifyNewUser{}, http.StatusBadRequest,
			v1.UserError{
				ErrorCode: v1.ErrorStatusVerificationTokenInvalid,
			}},

		{"success",
			v1.VerifyNewUser{
				Email:             usr.Email,
				VerificationToken: token,
				Signature:         sig,
			},
			http.StatusOK, nil},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			// Setup request
			q := url.Values{}
			q.Set("email", v.params.Email)
			q.Set("verificationtoken", v.params.VerificationToken)
			q.Set("signature", v.params.Signature)
			route := fmt.Sprintf("%v?%v", v1.RouteVerifyNewUser, q.Encode())
			r := httptest.NewRequest(http.MethodGet, route, nil)
			w := httptest.NewRecorder()

			// Run test case
			p.handleVerifyNewUser(w, r)
			res := w.Result()
			body, _ := ioutil.ReadAll(res.Body)

			// Validate response
			if res.StatusCode != v.wantStatusCode {
				t.Errorf("got status code %v, want %v",
					res.StatusCode, v.wantStatusCode)
			}

			if res.StatusCode == http.StatusOK {
				// No need to check for an error code
				// when the response status is a 200.
				return
			}

			var ue v1.UserError
			err = json.Unmarshal(body, &ue)
			if err != nil {
				t.Errorf("unmarshal UserError: %v", err)
			}

			got := errToStr(ue)
			want := errToStr(v.wantError)
			if got != want {
				t.Errorf("got error %v, want %v", got, want)
			}
		})
	}
}

func TestHandleUserDetails(t *testing.T) {
	p := newTestPoliteiawww(t)
	defer cleanupTestPoliteiawww(t, p)

	// Create a user whose details we can fetch
	usr, _ := newUser(t, p, false)

	// Setup tests
	var tests = []struct {
		name           string // Test name
		uuid           string // UUID for route param
		loggedIn       bool   // Should req contain a user session
		wantStatusCode int    // Want status code
		wantError      error  // Want error
	}{
		// The UUID is a route param so an invalid length UUID will
		// be caught by the router. A correct length UUID with an
		// invalid format will not be caught by the router and needs
		// to be tested for.
		{"invalid uuid format", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			false, http.StatusBadRequest,
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidInput,
			}},

		{"process user details error", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
			false, http.StatusBadRequest,
			v1.UserError{
				ErrorCode: v1.ErrorStatusUserNotFound,
			}},

		{"logged in user success", usr.ID.String(), true, http.StatusOK, nil},
		{"public user success", usr.ID.String(), false, http.StatusOK, nil},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			// Setup request
			r := httptest.NewRequest(http.MethodGet, v1.RouteUserDetails, nil)
			r = mux.SetURLVars(r, map[string]string{
				"userid": v.uuid,
			})
			w := httptest.NewRecorder()

			// Create a user session manually if the request
			// needs to be from a logged in user.
			if v.loggedIn {
				// Create new session
				_, err := p.getSession(r)
				if err != nil {
					t.Fatalf("%v", err)
				}

				// Set the session UUID param to make it appear as
				// though the user is logged in.
				err = p.setSessionUserID(w, r, usr.ID.String())
				if err != nil {
					t.Fatalf("%v", err)
				}
			}

			// Run test
			p.handleUserDetails(w, r)
			res := w.Result()
			body, _ := ioutil.ReadAll(res.Body)

			// Validate response
			if res.StatusCode != v.wantStatusCode {
				t.Errorf("got status code %v, want %v",
					res.StatusCode, v.wantStatusCode)
			}

			if res.StatusCode == http.StatusOK {
				// No need to check for an error code
				// when the response status is a 200.
				return
			}

			var ue v1.UserError
			err := json.Unmarshal(body, &ue)
			if err != nil {
				t.Errorf("unmarshal UserError: %v", err)
			}

			got := errToStr(ue)
			want := errToStr(v.wantError)
			if got != want {
				t.Errorf("got error %v, want %v", got, want)
			}
		})
	}
}
