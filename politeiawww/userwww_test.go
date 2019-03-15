// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	v1 "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/go-test/deep"
	"github.com/gorilla/mux"
)

func TestHandleNewUser(t *testing.T) {
	p := newTestPoliteiawww(t)
	defer cleanupTestPoliteiawww(t, p)

	id, err := identity.New()
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Setup tests
	var tests = []struct {
		name       string
		reqBody    interface{}
		wantStatus int
		wantError  error
	}{
		{"invalid request body", "", http.StatusBadRequest,
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidInput,
			}},

		{"processNewUser error", v1.NewUser{}, http.StatusBadRequest,
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidPublicKey,
			}},

		{"success",
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
			r := newPostReq(t, v1.RouteNewUser, v.reqBody)
			w := httptest.NewRecorder()

			// Run test case
			p.handleNewUser(w, r)
			res := w.Result()
			body, _ := ioutil.ReadAll(res.Body)

			// Validate response
			if res.StatusCode != v.wantStatus {
				t.Errorf("got status code %v, want %v",
					res.StatusCode, v.wantStatus)
			}

			if res.StatusCode == http.StatusOK {
				// Test case passes; next case
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
				t.Errorf("got error %v, want %v",
					got, want)
			}
		})
	}
}

func TestHandleVerifyNewUser(t *testing.T) {
	p := newTestPoliteiawww(t)
	defer cleanupTestPoliteiawww(t, p)

	// Create an unverified user to test against
	usr, id := newUser(t, p, false, false)
	token := hex.EncodeToString(usr.NewUserVerificationToken)
	s := id.SignMessage([]byte(token))
	sig := hex.EncodeToString(s[:])

	// Test invalid query param. We have to run it individually
	// so that we can set the wrong query param.
	t.Run("invalid query params", func(t *testing.T) {
		// Setup request
		r := httptest.NewRequest(http.MethodGet, v1.RouteVerifyNewUser, nil)
		w := httptest.NewRecorder()

		q := r.URL.Query()
		q.Add("hello", "world")
		r.URL.RawQuery = q.Encode()

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
		err := json.Unmarshal(body, &ue)
		if err != nil {
			t.Errorf("unmarshal UserError: %v", err)
		}

		got := errToStr(ue)
		want := v1.ErrorStatus[v1.ErrorStatusInvalidInput]
		if got != want {
			t.Errorf("got error %v, want %v",
				got, want)
		}
	})

	// Setup remaining tests
	var tests = []struct {
		name       string
		params     v1.VerifyNewUser
		wantStatus int
		wantError  error
	}{
		{"processVerifyNewUser error",
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
			r := httptest.NewRequest(http.MethodGet, v1.RouteVerifyNewUser, nil)
			w := httptest.NewRecorder()

			q := r.URL.Query()
			q.Add("email", v.params.Email)
			q.Add("verificationtoken", v.params.VerificationToken)
			q.Add("signature", v.params.Signature)
			r.URL.RawQuery = q.Encode()

			// Run test case
			p.handleVerifyNewUser(w, r)
			res := w.Result()
			body, _ := ioutil.ReadAll(res.Body)

			// Validate response
			if res.StatusCode != v.wantStatus {
				t.Errorf("got status code %v, want %v",
					res.StatusCode, v.wantStatus)
			}

			if res.StatusCode == http.StatusOK {
				// Test case passes; next case
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
				t.Errorf("got error %v, want %v",
					got, want)
			}
		})
	}
}

func TestHandleResendVerification(t *testing.T) {
	p := newTestPoliteiawww(t)
	defer cleanupTestPoliteiawww(t, p)

	// Create a verified user
	usrVerified, _ := newUser(t, p, true, false)

	// Create an unverified user that has already had the
	// verification email resent.
	usrResent, _ := newUser(t, p, false, false)
	usrResent.ResendNewUserVerificationExpiry = time.Now().Unix() + 100
	err := p.db.UserUpdate(*usrResent)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Create a user for the success case
	usr, id := newUser(t, p, false, false)
	usrPubkey := id.Public.String()

	// Setup tests
	var tests = []struct {
		name       string
		reqBody    interface{}
		wantStatus int
		wantError  error
	}{
		{"invalid request body", "", http.StatusBadRequest,
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidInput,
			}},

		{"user not found",
			v1.ResendVerification{
				Email:     "",
				PublicKey: usrPubkey,
			},
			http.StatusOK, nil},

		{"user already verified",
			v1.ResendVerification{
				Email: usrVerified.Email,
			},
			http.StatusOK, nil},

		{"verification already resent",
			v1.ResendVerification{
				Email: usrResent.Email,
			},
			http.StatusOK, nil},

		{"processResendVerification error",
			v1.ResendVerification{
				Email:     usr.Email,
				PublicKey: "abc",
			},
			http.StatusBadRequest,
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidPublicKey,
			}},

		{"success",
			v1.ResendVerification{
				Email:     usr.Email,
				PublicKey: usrPubkey,
			},
			http.StatusOK, nil},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			r := newPostReq(t, v1.RouteResendVerification, v.reqBody)
			w := httptest.NewRecorder()
			p.handleResendVerification(w, r)
			res := w.Result()
			body, _ := ioutil.ReadAll(res.Body)

			// Validate response
			if res.StatusCode != v.wantStatus {
				t.Errorf("got status code %v, want %v",
					res.StatusCode, v.wantStatus)
			}

			if res.StatusCode == http.StatusOK {
				// Test case passes; next case
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
				t.Errorf("got error %v, want %v",
					got, want)
			}
		})
	}
}

func TestHandleLogin(t *testing.T) {
	p := newTestPoliteiawww(t)
	defer cleanupTestPoliteiawww(t, p)

	// MinimumLoginWaitTime is a global variable used to
	// prevent timing attacks. We're not testing it here
	// so we zero it out to make the tests run faster.
	MinimumLoginWaitTime = 0

	// Create a user to test against. newUser() sets the
	// password to be the same as the username.
	u, _ := newUser(t, p, true, false)
	password := u.Username
	expectedReply, err := p.createLoginReply(u, u.LastLoginTime)
	if err != nil {
		t.Fatalf("%v", err)
	}
	expectedReply.SessionMaxAge = sessionMaxAge

	// Setup tests
	var tests = []struct {
		name       string
		reqBody    interface{}
		wantStatus int
		wantReply  *v1.LoginReply
		wantError  error
	}{
		{"invalid request body", "", http.StatusBadRequest, nil,
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidInput,
			}},

		{"processLogin error", v1.Login{}, http.StatusUnauthorized, nil,
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidEmailOrPassword,
			}},

		{"success",
			v1.Login{
				Email:    u.Email,
				Password: password,
			},
			http.StatusOK, expectedReply, nil},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			// Setup request
			r := newPostReq(t, v1.RouteLogin, v.reqBody)
			w := httptest.NewRecorder()

			// Run test case
			p.handleLogin(w, r)
			res := w.Result()
			body, _ := ioutil.ReadAll(res.Body)

			// Validate response
			if res.StatusCode != v.wantStatus {
				t.Errorf("got status code %v, want %v",
					res.StatusCode, v.wantStatus)
			}

			if res.StatusCode == http.StatusOK {
				// A user session should have been
				// created if login was successful.
				_, err := p.getSessionUser(w, r)
				if err != nil {
					t.Errorf("session not created")
				}

				// Check response body
				var lr v1.LoginReply
				err = json.Unmarshal(body, &lr)
				if err != nil {
					t.Errorf("unmarshal LoginReply: %v", err)
				}

				diff := deep.Equal(lr, *v.wantReply)
				if diff != nil {
					t.Errorf("LoginReply got/want diff:\n%v",
						spew.Sdump(diff))
				}

				// Test case passes; next case
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
				t.Errorf("got error %v, want %v",
					got, want)
			}
		})
	}
}

func TestHandleChangePassword(t *testing.T) {
	p := newTestPoliteiawww(t)
	defer cleanupTestPoliteiawww(t, p)

	// Create a user to test against. newUser()
	// sets the password to be the username.
	usr, _ := newUser(t, p, true, false)
	currPass := usr.Username
	newPass := currPass + "aaa"

	var tests = []struct {
		name       string
		reqBody    interface{}
		wantStatus int
		wantError  error
	}{
		// Middleware will catch any invalid user sessions.
		// We can assume that the request contains a valid
		// user session.

		{"invalid request body", "", http.StatusBadRequest,
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidInput,
			}},

		{"processChangePassword error",
			v1.ChangePassword{
				CurrentPassword: "",
				NewPassword:     newPass,
			},
			http.StatusBadRequest,
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidEmailOrPassword,
			}},

		{"success",
			v1.ChangePassword{
				CurrentPassword: currPass,
				NewPassword:     newPass,
			},
			http.StatusOK, nil},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			// Setup request
			r := newPostReq(t, v1.RouteChangePassword, v.reqBody)
			w := httptest.NewRecorder()

			// Set user session
			err := p.setSessionUserID(w, r, usr.ID.String())
			if err != nil {
				t.Fatalf("%v", err)
			}

			// Run test case
			p.handleChangePassword(w, r)
			res := w.Result()
			body, _ := ioutil.ReadAll(res.Body)

			// Validate response
			if res.StatusCode != v.wantStatus {
				t.Errorf("got status code %v, want %v",
					res.StatusCode, v.wantStatus)
			}

			if res.StatusCode == http.StatusOK {
				// Test case passes; next case
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
				t.Errorf("got error %v, want %v",
					got, want)
			}
		})
	}
}

func TestHandleResetPassword(t *testing.T) {
	p := newTestPoliteiawww(t)
	defer cleanupTestPoliteiawww(t, p)

	// Create a user that has already been assigned a reset
	// password verification token.
	usr, _ := newUser(t, p, true, false)
	newPass := usr.Username + "aaa"
	token, expiry, err := generateVerificationTokenAndExpiry()
	if err != nil {
		t.Fatalf("%v", err)
	}
	usr.ResetPasswordVerificationToken = token
	usr.ResetPasswordVerificationExpiry = expiry
	err = p.db.UserUpdate(*usr)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Setup tests
	var tests = []struct {
		name       string
		reqBody    interface{}
		wantStatus int
		wantError  error
	}{
		{"invalid request body", "", http.StatusBadRequest,
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidInput,
			}},

		{"user not found", v1.ResetPassword{}, http.StatusOK, nil},

		{"processResetPassword error",
			v1.ResetPassword{
				Email:             usr.Email,
				VerificationToken: hex.EncodeToString(token),
				NewPassword:       "x",
			},
			http.StatusBadRequest,
			v1.UserError{
				ErrorCode: v1.ErrorStatusMalformedPassword,
			}},

		{"success",
			v1.ResetPassword{
				Email:             usr.Email,
				VerificationToken: hex.EncodeToString(token),
				NewPassword:       newPass,
			},
			http.StatusOK, nil},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			// Setup request
			r := newPostReq(t, v1.RouteResetPassword, v.reqBody)
			w := httptest.NewRecorder()

			// Run test case
			p.handleResetPassword(w, r)
			res := w.Result()
			body, _ := ioutil.ReadAll(res.Body)

			// Validate response
			if res.StatusCode != v.wantStatus {
				t.Errorf("got status code %v, want %v",
					res.StatusCode, v.wantStatus)
			}

			if res.StatusCode == http.StatusOK {
				// Test case passes; next case
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
				t.Errorf("got error %v, want %v",
					got, want)
			}
		})
	}
}

func TestHandleChangeUsername(t *testing.T) {
	p := newTestPoliteiawww(t)
	defer cleanupTestPoliteiawww(t, p)

	// Create a user to test against. newUser()
	// sets the password to be the username.
	usr, _ := newUser(t, p, true, false)
	pass := usr.Username

	// Setup tests
	var tests = []struct {
		name       string
		reqBody    interface{}
		wantStatus int
		wantError  error
	}{
		// Middleware will catch any invalid user sessions.
		// We can assume that the request contains a valid
		// user session.

		{"invalid request body", "", http.StatusBadRequest,
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidInput,
			}},

		{"processChangeUsername error", v1.ChangeUsername{},
			http.StatusBadRequest,
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidEmailOrPassword,
			}},

		{"success",
			v1.ChangeUsername{
				Password:    pass,
				NewUsername: usr.Username + "aaa",
			},
			http.StatusOK, nil},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			// Setup request
			r := newPostReq(t, v1.RouteChangeUsername, v.reqBody)
			w := httptest.NewRecorder()

			// Set user session
			err := p.setSessionUserID(w, r, usr.ID.String())
			if err != nil {
				t.Fatalf("%v", err)
			}

			// Run test case
			p.handleChangeUsername(w, r)
			res := w.Result()
			body, _ := ioutil.ReadAll(res.Body)

			// Validate response
			if res.StatusCode != v.wantStatus {
				t.Errorf("got status code %v, want %v",
					res.StatusCode, v.wantStatus)
			}

			if res.StatusCode == http.StatusOK {
				// Test case passes; next case
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
				t.Errorf("got error %v, want %v",
					got, want)
			}
		})
	}
}

func TestHandleUserDetails(t *testing.T) {
	p := newTestPoliteiawww(t)
	defer cleanupTestPoliteiawww(t, p)

	// Create a user whose details we can fetch
	usr, _ := newUser(t, p, true, false)

	// Setup tests
	var tests = []struct {
		name       string // Test name
		uuid       string // UUID for route param
		loggedIn   bool   // Should request contain a user session
		wantStatus int    // Wanted response status code
		wantError  error  // Wanted response error
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

			// Set user session
			if v.loggedIn {
				err := p.setSessionUserID(w, r, usr.ID.String())
				if err != nil {
					t.Fatalf("%v", err)
				}
			}

			// Run test case
			p.handleUserDetails(w, r)
			res := w.Result()
			body, _ := ioutil.ReadAll(res.Body)

			// Validate response
			if res.StatusCode != v.wantStatus {
				t.Errorf("got status code %v, want %v",
					res.StatusCode, v.wantStatus)
			}

			if res.StatusCode == http.StatusOK {
				// Test case passes; next case
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
				t.Errorf("got error %v, want %v",
					got, want)
			}
		})
	}
}

func TestHandleEditUser(t *testing.T) {
	p := newTestPoliteiawww(t)
	defer cleanupTestPoliteiawww(t, p)

	var notif uint64 = 0x01
	usr, _ := newUser(t, p, true, true)

	var tests = []struct {
		name       string
		reqBody    interface{}
		wantStatus int
		wantError  error
	}{
		// Middleware will catch any invalid admin sessions.
		// We can assume that the request contains a valid
		// admin session.

		{"invalid request body", "", http.StatusBadRequest,
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidInput,
			}},

		{"success",
			v1.EditUser{
				EmailNotifications: &notif,
			},
			http.StatusOK, nil},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			// Setup request
			r := newPostReq(t, v1.RouteEditUser, v.reqBody)
			w := httptest.NewRecorder()

			// Set user session
			err := p.setSessionUserID(w, r, usr.ID.String())
			if err != nil {
				t.Fatalf("%v", err)
			}

			// Run test case
			p.handleEditUser(w, r)
			res := w.Result()
			body, _ := ioutil.ReadAll(res.Body)

			// Validate response
			if res.StatusCode != v.wantStatus {
				t.Errorf("got status code %v, want %v",
					res.StatusCode, v.wantStatus)
			}

			if res.StatusCode == http.StatusOK {
				// Test case passes; next case
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
				t.Errorf("got error %v, want %v",
					got, want)
			}
		})
	}
}
