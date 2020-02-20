// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/go-test/deep"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

// newPostReq returns an httptest post request that was created using the
// passed in data.
func newPostReq(t *testing.T, route string, body interface{}) *http.Request {
	t.Helper()

	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("%v", err)
	}

	return httptest.NewRequest(http.MethodPost, route,
		bytes.NewReader(b))
}

// addSessionToReq initializes a user session and adds a session cookie to the
// given http request. The user session is saved to the politeiawww session
// store during intialization.
func addSessionToReq(t *testing.T, p *politeiawww, req *http.Request, userID string) {
	t.Helper()

	// Init session adds a session cookie onto the http response.
	r := httptest.NewRequest(http.MethodGet, "/", bytes.NewReader([]byte{}))
	w := httptest.NewRecorder()
	err := p.initSession(w, r, userID)
	if err != nil {
		t.Fatal(err)
	}
	res := w.Result()
	res.Body.Close()

	// Grab the session cookie from the response and add it to the
	// request.
	var c *http.Cookie
	for _, v := range res.Cookies() {
		if v.Name == www.CookieSession {
			c = v
			break
		}
	}
	req.AddCookie(c)

	// Verify the session was added successfully.
	s, err := p.getSession(req)
	if err != nil {
		t.Fatal(err)
	}
	if s.IsNew {
		t.Fatal("session not found in store")
	}
}

func TestHandleNewUser(t *testing.T) {
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

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
		{
			"invalid request body",
			"",
			http.StatusBadRequest,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			},
		},
		{
			"processNewUser error",
			www.NewUser{},
			http.StatusBadRequest,
			www.UserError{
				ErrorCode: www.ErrorStatusMalformedEmail,
			},
		},
		{
			"success",
			www.NewUser{
				Email:     "user@example.com",
				Password:  "password",
				PublicKey: hex.EncodeToString(id.Public.Key[:]),
				Username:  "user",
			},
			http.StatusOK,
			nil,
		},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			// Setup request
			r := newPostReq(t, www.RouteNewUser, v.reqBody)
			w := httptest.NewRecorder()

			// Run test case
			p.handleNewUser(w, r)
			res := w.Result()
			body, _ := ioutil.ReadAll(res.Body)
			res.Body.Close()

			// Validate response
			if res.StatusCode != v.wantStatus {
				t.Errorf("got status code %v, want %v",
					res.StatusCode, v.wantStatus)
			}

			if res.StatusCode == http.StatusOK {
				// Test case passes; next case
				return
			}

			var ue www.UserError
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
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	// Create an unverified user to test against
	usr, id := newUser(t, p, false, false)
	token := hex.EncodeToString(usr.NewUserVerificationToken)
	s := id.SignMessage([]byte(token))
	sig := hex.EncodeToString(s[:])

	// Test invalid query param. We have to run it individually
	// so that we can set the wrong query param.
	t.Run("invalid query params", func(t *testing.T) {
		// Setup request
		r := httptest.NewRequest(http.MethodGet, www.RouteVerifyNewUser, nil)
		w := httptest.NewRecorder()

		q := r.URL.Query()
		q.Add("hello", "world")
		r.URL.RawQuery = q.Encode()

		// Run test case
		p.handleVerifyNewUser(w, r)
		res := w.Result()
		body, _ := ioutil.ReadAll(res.Body)
		res.Body.Close()

		// Validate response
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("got status code %v, want %v",
				res.StatusCode, http.StatusBadRequest)
		}

		var ue www.UserError
		err := json.Unmarshal(body, &ue)
		if err != nil {
			t.Errorf("unmarshal UserError: %v", err)
		}

		got := errToStr(ue)
		want := www.ErrorStatus[www.ErrorStatusInvalidInput]
		if got != want {
			t.Errorf("got error %v, want %v",
				got, want)
		}
	})

	// Setup remaining tests
	var tests = []struct {
		name       string
		params     www.VerifyNewUser
		wantStatus int
		wantError  error
	}{
		{"processVerifyNewUser error",
			www.VerifyNewUser{}, http.StatusBadRequest,
			www.UserError{
				ErrorCode: www.ErrorStatusVerificationTokenInvalid,
			}},

		{"success",
			www.VerifyNewUser{
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
			r := httptest.NewRequest(http.MethodGet, www.RouteVerifyNewUser, nil)
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
			res.Body.Close()

			// Validate response
			if res.StatusCode != v.wantStatus {
				t.Errorf("got status code %v, want %v",
					res.StatusCode, v.wantStatus)
			}

			if res.StatusCode == http.StatusOK {
				// Test case passes; next case
				return
			}

			var ue www.UserError
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
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

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
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			}},

		{"user not found",
			www.ResendVerification{
				Email:     "",
				PublicKey: usrPubkey,
			},
			http.StatusOK, nil},

		{"user already verified",
			www.ResendVerification{
				Email: usrVerified.Email,
			},
			http.StatusOK, nil},

		{"verification already resent",
			www.ResendVerification{
				Email: usrResent.Email,
			},
			http.StatusOK, nil},

		{"processResendVerification error",
			www.ResendVerification{
				Email:     usr.Email,
				PublicKey: "abc",
			},
			http.StatusBadRequest,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidPublicKey,
			}},

		{"success",
			www.ResendVerification{
				Email:     usr.Email,
				PublicKey: usrPubkey,
			},
			http.StatusOK, nil},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			r := newPostReq(t, www.RouteResendVerification, v.reqBody)
			w := httptest.NewRecorder()
			p.handleResendVerification(w, r)
			res := w.Result()
			body, _ := ioutil.ReadAll(res.Body)
			res.Body.Close()

			// Validate response
			if res.StatusCode != v.wantStatus {
				t.Errorf("got status code %v, want %v",
					res.StatusCode, v.wantStatus)
			}

			if res.StatusCode == http.StatusOK {
				// Test case passes; next case
				return
			}

			var ue www.UserError
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
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	// loginMinWaitTime is a global variable used to prevent
	// timing attacks. We're not testing it here so we
	// temporarily zero it out to make the tests run faster.
	m := loginMinWaitTime
	loginMinWaitTime = 0
	defer func() {
		loginMinWaitTime = m
	}()

	// Create a user to test against. newUser() sets the
	// password to be the same as the username.
	u, _ := newUser(t, p, true, false)
	password := u.Username
	successReply, err := p.createLoginReply(u, u.LastLoginTime)
	if err != nil {
		t.Fatalf("%v", err)
	}
	successReply.SessionMaxAge = sessionMaxAge

	// Setup tests
	var tests = []struct {
		name       string
		reqBody    interface{}
		wantStatus int
		wantReply  *www.LoginReply
		wantError  error
	}{
		{
			"invalid request body",
			"",
			http.StatusBadRequest,
			nil,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			},
		},
		{
			"processLogin error",
			www.Login{},
			http.StatusUnauthorized,
			nil,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidLogin,
			},
		},
		{
			"success",
			www.Login{
				Email:    u.Email,
				Password: password,
			},
			http.StatusOK,
			successReply,
			nil,
		},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			// Setup request
			r := newPostReq(t, www.RouteLogin, v.reqBody)
			w := httptest.NewRecorder()

			// Run test case
			p.handleLogin(w, r)
			res := w.Result()
			body, _ := ioutil.ReadAll(res.Body)
			res.Body.Close()

			// Validate response
			if res.StatusCode != v.wantStatus {
				t.Errorf("got status code %v, want %v",
					res.StatusCode, v.wantStatus)
			}

			if res.StatusCode == http.StatusOK {
				// A user session should have been added to the response
				// cookie.
				var sessionID string
				for _, v := range res.Cookies() {
					if v.Name == www.CookieSession && v.Value != "" {
						sessionID = v.Value
					}
				}
				if sessionID == "" {
					t.Errorf("no session cookie in response")
				}

				// A user session should have been added to the session
				// store. The best way to check this is to add a session
				// cookie onto a request and use the getSession() method.
				req := httptest.NewRequest(http.MethodGet, "/",
					bytes.NewReader([]byte{}))
				opts := newSessionOptions()
				c := sessions.NewCookie(www.CookieSession, sessionID, opts)
				req.AddCookie(c)
				s, err := p.getSession(req)
				if err != nil {
					t.Error(err)
				}
				if s.IsNew {
					t.Errorf("session not saved to session store")
				}

				// Check response body
				var lr www.LoginReply
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

			var ue www.UserError
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

/*
XXX these tests are for the login implementation that uses username instead of
email. They are being commented out until we switch the login credentials back
to username.
https://github.com/decred/politeia/issues/860#issuecomment-520871500

func TestHandleLogin(t *testing.T) {
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	// Create a user to test against. newUser() sets the
	// password to be the same as the username.
	u, _ := newUser(t, p, true, false)
	password := u.Username
	expectedReply, err := p.createLoginReply(u, u.LastLoginTime)
	if err != nil {
		t.Fatal(err)
	}
	expectedReply.SessionMaxAge = sessionMaxAge

	// Setup tests
	var tests = []struct {
		name       string
		reqBody    interface{}
		wantStatus int
		wantReply  *www.LoginReply
		wantError  error
	}{
		{
			"invalid request body",
			"",
			http.StatusBadRequest,
			nil,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			},
		},
		{
			"processLogin error",
			www.Login{},
			http.StatusUnauthorized,
			nil,
			www.UserError{
				ErrorCode: www.ErrorStatusUserNotFound,
			},
		},
		{
			"success",
			www.Login{
				Username: u.Username,
				Password: password,
			},
			http.StatusOK,
			expectedReply,
			nil,
		},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			// Setup request
			r := newPostReq(t, www.RouteLogin, v.reqBody)
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
				var lr www.LoginReply
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

			var ue www.UserError
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
*/

func TestHandleChangePassword(t *testing.T) {
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

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
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			}},

		{"processChangePassword error",
			www.ChangePassword{
				CurrentPassword: "",
				NewPassword:     newPass,
			},
			http.StatusBadRequest,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidPassword,
			}},

		{"success",
			www.ChangePassword{
				CurrentPassword: currPass,
				NewPassword:     newPass,
			},
			http.StatusOK, nil},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			// Setup request
			r := newPostReq(t, www.RouteChangePassword, v.reqBody)
			addSessionToReq(t, p, r, usr.ID.String())
			w := httptest.NewRecorder()

			// Run test case
			p.handleChangePassword(w, r)
			res := w.Result()
			body, _ := ioutil.ReadAll(res.Body)
			res.Body.Close()

			// Validate response
			if res.StatusCode != v.wantStatus {
				t.Errorf("got status code %v, want %v",
					res.StatusCode, v.wantStatus)
			}

			if res.StatusCode == http.StatusOK {
				// Test case passes; next case
				return
			}

			var ue www.UserError
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

func TestHandleResetPassword(t *testing.T) {
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	// Create a test user
	usr, _ := newUser(t, p, true, false)

	// Remove the min wait time requirement so that the tests
	// aren't slow.
	wt := resetPasswordMinWaitTime
	resetPasswordMinWaitTime = 0 * time.Millisecond
	defer func() {
		resetPasswordMinWaitTime = wt
	}()

	// Setup tests
	var tests = []struct {
		name       string
		reqBody    interface{}
		wantStatus int // HTTP status code
		wantError  error
	}{
		{
			"invalid request body",
			"",
			http.StatusBadRequest,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			},
		},
		{
			"processResetPassword error",
			www.ResetPassword{
				Username: "wrongusername",
			},
			http.StatusBadRequest,
			www.UserError{
				ErrorCode: www.ErrorStatusUserNotFound,
			},
		},
		{
			"success",
			www.ResetPassword{
				Username: usr.Username,
				Email:    usr.Email,
			},
			http.StatusOK,
			nil,
		},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			// Setup request
			r := newPostReq(t, www.RouteResetPassword, v.reqBody)
			w := httptest.NewRecorder()

			// Run test case
			p.handleResetPassword(w, r)
			res := w.Result()
			body, _ := ioutil.ReadAll(res.Body)
			res.Body.Close()

			// Validate response
			if res.StatusCode != v.wantStatus {
				t.Errorf("got status code %v, want %v",
					res.StatusCode, v.wantStatus)
			}

			if res.StatusCode == http.StatusOK {
				// Test case passes; next case
				return
			}

			var ue www.UserError
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

func TestHandleVerifyResetPassword(t *testing.T) {
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	// Create a user that has already been assigned a reset
	// password verification token.
	usr, _ := newUser(t, p, true, false)
	token, expiry, err := newVerificationTokenAndExpiry()
	if err != nil {
		t.Fatal(err)
	}
	usr.ResetPasswordVerificationToken = token
	usr.ResetPasswordVerificationExpiry = expiry
	err = p.db.UserUpdate(*usr)
	if err != nil {
		t.Fatal(err)
	}
	verificationToken := hex.EncodeToString(token)

	// Setup tests
	var tests = []struct {
		name       string
		reqBody    interface{}
		wantStatus int // HTTP status code
		wantErr    error
	}{
		{
			"invalid request body",
			"",
			http.StatusBadRequest,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			},
		},
		{
			"processVerifyResetPassword error",
			www.VerifyResetPassword{
				Username: "wrongusername",
			},
			http.StatusBadRequest,
			www.UserError{
				ErrorCode: www.ErrorStatusUserNotFound,
			},
		},
		{
			"success",
			www.VerifyResetPassword{
				Username:          usr.Username,
				VerificationToken: verificationToken,
				NewPassword:       "helloworld",
			},
			http.StatusOK,
			nil,
		},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			// Setup request
			r := newPostReq(t, www.RouteVerifyResetPassword, v.reqBody)
			w := httptest.NewRecorder()

			// Run test case
			p.handleVerifyResetPassword(w, r)
			res := w.Result()
			body, _ := ioutil.ReadAll(res.Body)
			res.Body.Close()

			// Check status code
			if res.StatusCode != v.wantStatus {
				t.Errorf("got status code %v, want %v",
					res.StatusCode, v.wantStatus)
			}
			if res.StatusCode == http.StatusOK {
				// Test case passes; next case
				return
			}

			// Check user error
			var ue www.UserError
			err := json.Unmarshal(body, &ue)
			if err != nil {
				t.Errorf("unmarshal UserError: %v", err)
			}
			got := errToStr(ue)
			want := errToStr(v.wantErr)
			if got != want {
				t.Errorf("got error %v, want %v", got, want)
			}
		})
	}
}

func TestHandleChangeUsername(t *testing.T) {
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

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
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			}},

		{"processChangeUsername error", www.ChangeUsername{},
			http.StatusBadRequest,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidPassword,
			}},

		{"success",
			www.ChangeUsername{
				Password:    pass,
				NewUsername: usr.Username + "aaa",
			},
			http.StatusOK, nil},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			// Setup request
			r := newPostReq(t, www.RouteChangeUsername, v.reqBody)
			addSessionToReq(t, p, r, usr.ID.String())
			w := httptest.NewRecorder()

			// Run test case
			p.handleChangeUsername(w, r)
			res := w.Result()
			body, _ := ioutil.ReadAll(res.Body)
			res.Body.Close()

			// Validate response
			if res.StatusCode != v.wantStatus {
				t.Errorf("got status code %v, want %v",
					res.StatusCode, v.wantStatus)
			}

			if res.StatusCode == http.StatusOK {
				// Test case passes; next case
				return
			}

			var ue www.UserError
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

func TestHandleUserDetails(t *testing.T) {
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

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
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			}},

		{"process user details error", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
			false, http.StatusBadRequest,
			www.UserError{
				ErrorCode: www.ErrorStatusUserNotFound,
			}},

		{"logged in user success", usr.ID.String(), true, http.StatusOK, nil},
		{"public user success", usr.ID.String(), false, http.StatusOK, nil},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			// Setup request
			r := httptest.NewRequest(http.MethodGet, www.RouteUserDetails, nil)
			r = mux.SetURLVars(r, map[string]string{
				"userid": v.uuid,
			})
			w := httptest.NewRecorder()

			// Initialize the user session
			if v.loggedIn {
				err := p.initSession(w, r, usr.ID.String())
				if err != nil {
					t.Fatalf("%v", err)
				}
			}

			// Run test case
			p.handleUserDetails(w, r)
			res := w.Result()
			body, _ := ioutil.ReadAll(res.Body)
			res.Body.Close()

			// Validate response
			if res.StatusCode != v.wantStatus {
				t.Errorf("got status code %v, want %v",
					res.StatusCode, v.wantStatus)
			}

			if res.StatusCode == http.StatusOK {
				// Test case passes; next case
				return
			}

			var ue www.UserError
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
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

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
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			}},

		{"success",
			www.EditUser{
				EmailNotifications: &notif,
			},
			http.StatusOK, nil},
	}

	// Run tests
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			// Setup request
			r := newPostReq(t, www.RouteEditUser, v.reqBody)
			addSessionToReq(t, p, r, usr.ID.String())
			w := httptest.NewRecorder()

			// Run test case
			p.handleEditUser(w, r)
			res := w.Result()
			body, _ := ioutil.ReadAll(res.Body)
			res.Body.Close()

			// Validate response
			if res.StatusCode != v.wantStatus {
				t.Errorf("got status code %v, want %v",
					res.StatusCode, v.wantStatus)
			}

			if res.StatusCode == http.StatusOK {
				// Test case passes; next case
				return
			}

			var ue www.UserError
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
