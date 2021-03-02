package main

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/davecgh/go-spew/spew"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/util/version"
	"github.com/go-test/deep"
)

func TestHandleVersion(t *testing.T) {
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	d := newTestPoliteiad(t, p)
	defer d.Close()

	expectedReply := www.VersionReply{
		Version:      www.PoliteiaWWWAPIVersion,
		BuildVersion: version.BuildMainVersion(),
		Route:        www.PoliteiaWWWAPIRoute,
		PubKey:       hex.EncodeToString(p.cfg.Identity.Key[:]),
		TestNet:      p.cfg.TestNet,
	}

	var tests = []struct {
		name       string
		wantReply  www.VersionReply
		wantStatus int
		wantError  error
	}{
		{
			"success",
			expectedReply,
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
			res.Body.Close()

			// Unmarshal body response
			var gotReply www.VersionReply
			err := json.Unmarshal(body, &gotReply)
			if err != nil {
				t.Errorf("unmarshal error with body %v", body)
			}

			// Validate response status
			if res.StatusCode != v.wantStatus {
				t.Errorf("got status code %v, want %v",
					res.StatusCode, v.wantStatus)
			}

			// Validate response body
			diff := deep.Equal(gotReply, v.wantReply)
			if diff != nil {
				t.Errorf("VersionReply got/want diff:\n%v",
					spew.Sdump(diff))
			}
		})
	}
}
