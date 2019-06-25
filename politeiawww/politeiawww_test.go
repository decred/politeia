package main

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/decred/politeia/politeiad/api/v1/identity"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
)

func TestHandleVersion(t *testing.T) {
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	id, err := identity.New()
	if err != nil {
		t.Fatalf("%v", err)
	}

	p.cfg.Identity = &id.Public

	expectedResponse := www.VersionReply{
		Version: www.PoliteiaWWWAPIVersion,
		Route:   www.PoliteiaWWWAPIRoute,
		PubKey:  hex.EncodeToString(p.cfg.Identity.Key[:]),
		TestNet: p.cfg.TestNet,
	}

	var tests = []struct {
		name         string
		wantResponse interface{}
		wantStatus   int
		wantError    error
	}{
		{
			"version call success",
			expectedResponse,
			http.StatusOK,
			nil,
		},
	}

	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			// Setup request
			r := httptest.NewRequest(http.MethodGet, www.RouteVersion, nil)
			w := httptest.NewRecorder()

			// Run test case
			p.handleVersion(w, r)
			res := w.Result()
			body, _ := ioutil.ReadAll(res.Body)

			// Unmarshal body response
			var receivedResponse www.VersionReply
			err := json.Unmarshal(body, &receivedResponse)
			if err != nil {
				t.Errorf("unmarshal error with body %v", body)
			}

			// Validate response status
			if res.StatusCode != v.wantStatus {
				t.Errorf("got status code %v, want %v", res.StatusCode, v.wantStatus)
			}

			// Validate that response body is what we expect
			if !reflect.DeepEqual(receivedResponse, expectedResponse) {
				t.Errorf("got response body %v, expected %v", receivedResponse, expectedResponse)
			}

			// Test case passed; next case
			if res.StatusCode == http.StatusOK {
				return
			}

			// Get user error if test failed
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
