package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/pquerna/otp/totp"
)

func TestSetTOTP(t *testing.T) {
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	usr, _ := newUser(t, p, true, false)

	var tests = []struct {
		name       string
		body       www.SetTOTP
		u          user.User
		setAgain   bool
		wantStatus int
		wantError  error
	}{
		{
			"success set/verify",
			www.SetTOTP{
				Type: www.TOTPTypeBasic,
			},
			*usr,
			false,
			http.StatusOK,
			nil,
		},
		{
			"error setting after set",
			www.SetTOTP{
				Type: www.TOTPTypeBasic,
				Code: "12345",
			},
			*usr,
			true,
			http.StatusBadRequest,
			www.UserError{
				ErrorCode: www.ErrorStatusTOTPFailedValidation,
			},
		},
	}

	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			// Prepare request and receive
			r := newPostReq(t, www.RouteSetTOTP, v.body)
			w := httptest.NewRecorder()

			p.handleSetTOTP(w, r)
			res := w.Result()
			body, _ := ioutil.ReadAll(res.Body)
			res.Body.Close()

			var gotReply www.SetTOTPReply
			err := json.Unmarshal(body, &gotReply)
			if err != nil {
				t.Errorf("unmarshal error with body %v", body)
			}

			// Validate http status code
			if res.StatusCode != v.wantStatus && !v.setAgain {
				t.Errorf("got status code %v, want %v",
					res.StatusCode, v.wantStatus)
			}

			code, err := totp.GenerateCode(gotReply.Key, time.Now())
			if err != nil {
				t.Errorf("unable to generate code %v", err)
			}

			r = newPostReq(t, www.RouteVerifyTOTP, www.VerifyTOTP{
				Code: code,
			})
			w = httptest.NewRecorder()

			p.handleVerifyTOTP(w, r)
			res = w.Result()
			body, _ = ioutil.ReadAll(res.Body)
			res.Body.Close()

			err = json.Unmarshal(body, &gotReply)
			if err != nil {
				t.Errorf("unmarshal error with body %v", body)
			}

			if v.setAgain {
				r = newPostReq(t, www.RouteVerifyTOTP, www.VerifyTOTP{
					Code: v.body.Code,
				})
				w = httptest.NewRecorder()

				p.handleVerifyTOTP(w, r)
				res = w.Result()
				body, _ = ioutil.ReadAll(res.Body)
				res.Body.Close()

				err = json.Unmarshal(body, &gotReply)
				if err != nil {
					t.Errorf("unmarshal error with body %v", body)
				}

				// Validate http status code
				if res.StatusCode != v.wantStatus {
					t.Errorf("got status code %v, want %v",
						res.StatusCode, v.wantStatus)
				}
			}
		})
	}
}
