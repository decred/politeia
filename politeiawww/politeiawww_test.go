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
	"github.com/go-test/deep"
)

func TestHandleVersion(t *testing.T) {
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	d := newTestPoliteiad(t, p)
	defer d.Close()

	expectedReply := www.VersionReply{
		Version: www.PoliteiaWWWAPIVersion,
		Route:   www.PoliteiaWWWAPIRoute,
		PubKey:  hex.EncodeToString(p.cfg.Identity.Key[:]),
		TestNet: p.cfg.TestNet,
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

func TestCountersAddPositiveValue(t *testing.T) {
	var cs counters = counters{up: 1, down: 1}
	cs.add(2)
	want := counters{up: 3, down: 1}
	if cs != want {
		t.Errorf("error, got %v, want %v", cs, want)
	}
}

func TestCountersAddNegativeValue(t *testing.T) {
	var cs counters = counters{up: 1, down: 1}
	cs.add(-3)
	want := counters{up: 1, down: 4}
	if cs != want {
		t.Errorf("error, got %v, want %v", cs, want)
	}
}

func TestCountersAddZero(t *testing.T) {
	var cs counters = counters{up: 1, down: 1}
	cs.add(0)
	want := counters{up: 1, down: 1}
	if cs != want {
		t.Errorf("error, got %v, want %v", cs, want)
	}
}

func TestCountersSubtractPositiveValue(t *testing.T) {
	var cs counters = counters{up: 5, down: 6}
	cs.subtract(2)
	want := counters{up: 3, down: 6}
	if cs != want {
		t.Errorf("error, got %v, want %v", cs, want)
	}
}

func TestCountersSubtractNegativeValue(t *testing.T) {
	var cs counters = counters{up: 5, down: 6}
	cs.subtract(-3)
	want := counters{up: 5, down: 3}
	if cs != want {
		t.Errorf("error, got %v, want %v", cs, want)
	}
}

func TestCountersSubtractZero(t *testing.T) {
	var cs counters = counters{up: 1, down: 1}
	cs.subtract(0)
	want := counters{up: 1, down: 1}
	if cs != want {
		t.Errorf("error, got %v, want %v", cs, want)
	}
}
