package main

import (
	"net/http"
	"testing"

	www "github.com/decred/politeia/politeiawww/api/www/v1"
)

func TestSetTOTP(t *testing.T) {
	_, cleanup := newTestPoliteiawww(t)
	defer cleanup()

	expectedReply := www.SetTOTPRepy{}

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
		})
	}
}
