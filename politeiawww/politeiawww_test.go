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

func TestHandleAllVetted(t *testing.T) {
	p, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	d := newTestPoliteiad(t, p)
	defer d.Close()

	admin, id := newUser(t, p, true, true)

	propPublic := newProposalRecord(t, admin, id, www.PropStatusPublic)
	propAbandoned := newProposalRecord(t, admin, id, www.PropStatusAbandoned)
	propUnvetted := newProposalRecord(t, admin, id, www.PropStatusNotReviewed)
	propCensored := newProposalRecord(t, admin, id, www.PropStatusCensored)

	d.AddRecord(t, convertPropToPD(t, propPublic))
	d.AddRecord(t, convertPropToPD(t, propAbandoned))
	d.AddRecord(t, convertPropToPD(t, propUnvetted))
	d.AddRecord(t, convertPropToPD(t, propCensored))

	var tests = []struct {
		name       string
		params     www.GetAllVetted
		badParams  bool
		wantProps  []string
		wantStatus int
		wantError  error
	}{
		{
			"bad request parameters",
			www.GetAllVetted{},
			true,
			[]string{},
			http.StatusBadRequest,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			},
		},
		{
			"bad data in request parameters",
			www.GetAllVetted{
				After: "bad-token",
			},
			false,
			[]string{},
			http.StatusBadRequest,
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidCensorshipToken,
			},
		},
		{
			"success",
			www.GetAllVetted{},
			false,
			[]string{
				propPublic.CensorshipRecord.Token,
				propAbandoned.CensorshipRecord.Token,
			},
			http.StatusOK,
			nil,
		},
	}

	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			// Prepare request and receive reply
			r := httptest.NewRequest(http.MethodGet, www.RouteAllVetted, nil)
			w := httptest.NewRecorder()

			q := r.URL.Query()

			if v.badParams {
				q.Add("bad", "param")
			} else {
				q.Add("before", v.params.Before)
				q.Add("after", v.params.After)
			}

			r.URL.RawQuery = q.Encode()

			p.handleAllVetted(w, r)
			res := w.Result()
			body, _ := ioutil.ReadAll(res.Body)
			res.Body.Close()

			var gotReply www.GetAllVettedReply
			err := json.Unmarshal(body, &gotReply)
			if err != nil {
				t.Errorf("unmarshal error with body %v", body)
			}

			// Validate http status code
			if res.StatusCode != v.wantStatus {
				t.Errorf("got status code %v, want %v",
					res.StatusCode, v.wantStatus)
			}

			// Make sure that correct proposals were received
			tokensMap := make(map[string]string)
			for _, prop := range gotReply.Proposals {
				token := prop.CensorshipRecord.Token
				tokensMap[token] = token
			}
			for _, token := range v.wantProps {
				if _, ok := tokensMap[token]; !ok {
					t.Errorf("proposal %v not present in reply", token)
				}
			}

			// Check if request was successful
			if res.StatusCode == http.StatusOK {
				return
			}

			// Receive user error when request fails
			var ue www.UserError
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
